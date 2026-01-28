package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TTLOrphanedReportCleanupReconciler cleans up orphaned reports in alternative storage
// when their parent Kubernetes resources have been deleted and their TTL has expired.
type TTLOrphanedReportCleanupReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	ext.Clock
	cleanupInterval time.Duration
}

// reportMetadata contains the essential metadata needed for cleanup decisions
type reportMetadata struct {
	Name              string
	Namespace         string
	Kind              string
	ResourceName      string
	CreationTimestamp time.Time
	TTL               *time.Duration
}

// reportDirectory defines a report type and its storage directory
type reportDirectory struct {
	Name string
	Path string
}

// SetupWithManager sets up the controller with the Manager.
func (r *TTLOrphanedReportCleanupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Add this as a runnable to the manager
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed to add cleanup controller as runnable: %w", err)
	}

	r.Info("Registered orphaned report cleanup controller",
		"interval", r.cleanupInterval,
		"reportDir", r.AltReportDir)

	return nil
}

// Start runs the periodic cleanup loop
func (r *TTLOrphanedReportCleanupReconciler) Start(ctx context.Context) error {
	ticker := time.NewTicker(r.cleanupInterval)
	defer ticker.Stop()

	r.Info("Orphaned report cleanup controller started")

	for {
		select {
		case <-ctx.Done():
			r.Info("Orphaned report cleanup controller stopped")
			return nil
		case <-ticker.C:
			if err := r.runCleanup(ctx); err != nil {
				r.Error(err, "Cleanup cycle failed")
			}
		}
	}
}

// runCleanup performs a single cleanup cycle across all report directories
func (r *TTLOrphanedReportCleanupReconciler) runCleanup(ctx context.Context) error {
	startTime := r.Now()
	totalChecked := 0
	totalDeleted := 0

	reportDirs := r.getReportDirectories()

	for _, dir := range reportDirs {
		checked, deleted, err := r.cleanupReportDirectory(ctx, dir.Path, dir.Name)
		if err != nil {
			r.Error(err, "Failed to cleanup directory", "directory", dir.Name)
			// Continue with other directories even if one fails
		}
		totalChecked += checked
		totalDeleted += deleted
	}

	duration := r.Now().Sub(startTime)
	r.Info("Cleanup cycle completed",
		"totalChecked", totalChecked,
		"totalDeleted", totalDeleted,
		"duration", duration)

	return nil
}

// getReportDirectories returns all report directories to clean
func (r *TTLOrphanedReportCleanupReconciler) getReportDirectories() []reportDirectory {
	baseDir := r.AltReportDir
	return []reportDirectory{
		{Name: "vulnerability_reports", Path: filepath.Join(baseDir, "vulnerability_reports")},
		{Name: "cluster_vulnerability_reports", Path: filepath.Join(baseDir, "cluster_vulnerability_reports")},
		{Name: "secret_reports", Path: filepath.Join(baseDir, "secret_reports")},
		{Name: "sbom_reports", Path: filepath.Join(baseDir, "sbom_reports")},
		{Name: "cluster_sbom_reports", Path: filepath.Join(baseDir, "cluster_sbom_reports")},
		{Name: "config_audit_reports", Path: filepath.Join(baseDir, "config_audit_reports")},
		{Name: "rbac_assessment_reports", Path: filepath.Join(baseDir, "rbac_assessment_reports")},
		{Name: "infra_assessment_reports", Path: filepath.Join(baseDir, "infra_assessment_reports")},
		{Name: "cluster_rbac_assessment_reports", Path: filepath.Join(baseDir, "cluster_rbac_assessment_reports")},
	}
}

// cleanupReportDirectory processes all reports in a single directory
func (r *TTLOrphanedReportCleanupReconciler) cleanupReportDirectory(ctx context.Context, dirPath, dirName string) (checked int, deleted int, err error) {
	// Check if directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		r.V(1).Info("Report directory does not exist, skipping", "directory", dirName)
		return 0, 0, nil
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read directory %s: %w", dirName, err)
	}

	for _, entry := range entries {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return checked, deleted, ctx.Err()
		default:
		}

		if entry.IsDir() {
			continue
		}

		// Only process JSON files
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		checked++
		filePath := filepath.Join(dirPath, entry.Name())

		// Parse report metadata
		metadata, err := r.parseReportFile(filePath)
		if err != nil {
			r.Error(err, "Failed to parse report file", "file", entry.Name())
			continue
		}

		// Skip reports without TTL annotation or ownerReferences (nil metadata)
		if metadata == nil {
			r.V(1).Info("Skipped report (no TTL annotation or ownerReferences)", "file", entry.Name())
			continue
		}

		// Check if report should be deleted
		shouldDelete, reason := r.shouldDeleteReport(ctx, metadata)
		if shouldDelete {
			if err := os.Remove(filePath); err != nil {
				r.Error(err, "Failed to delete report file", "file", entry.Name())
				continue
			}

			deleted++
			r.Info("Deleted orphaned report",
				"path", filePath,
				"reason", reason,
				"kind", metadata.Kind,
				"name", metadata.ResourceName,
				"namespace", metadata.Namespace)
		} else {
			r.V(1).Info("Skipped report",
				"file", entry.Name(),
				"reason", reason,
				"kind", metadata.Kind,
				"name", metadata.ResourceName)
		}
	}

	return checked, deleted, nil
}

// reportJSON represents the structure of a report file (either object or array element)
type reportJSON struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		CreationTimestamp string            `json:"creationTimestamp"`
		Annotations       map[string]string `json:"annotations"`
		OwnerReferences   []struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			UID        string `json:"uid"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Report struct {
		UpdateTimestamp string `json:"updateTimestamp"`
	} `json:"report"`
}

// parseReportFile extracts metadata from a report JSON file.
// Returns nil, nil if the report should be skipped (no TTL annotation or no ownerReferences).
// Returns nil, error only for actual parsing errors.
func (r *TTLOrphanedReportCleanupReconciler) parseReportFile(filePath string) (*reportMetadata, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as object first, then as array
	var obj reportJSON
	if err := json.Unmarshal(data, &obj); err != nil {
		// Try parsing as array (SBOM reports are stored as arrays)
		var arr []reportJSON
		if arrErr := json.Unmarshal(data, &arr); arrErr != nil {
			return nil, fmt.Errorf("failed to parse JSON as object or array: %w", err)
		}
		if len(arr) == 0 {
			return nil, fmt.Errorf("empty JSON array")
		}
		obj = arr[0] // Use first element's metadata
	}

	// Check if TTL annotation exists - skip silently if not present
	ttlStr, hasTTL := obj.Metadata.Annotations[v1alpha1.TTLReportAnnotation]
	if !hasTTL {
		return nil, nil // Skip: no TTL annotation
	}

	// Check if ownerReferences exist - skip silently if empty
	if len(obj.Metadata.OwnerReferences) == 0 {
		return nil, nil // Skip: no ownerReferences
	}

	// Parse TTL duration
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TTL annotation %q: %w", ttlStr, err)
	}

	// Extract kind and name from first ownerReference
	ownerRef := obj.Metadata.OwnerReferences[0]

	metadata := &reportMetadata{
		Name:         obj.Metadata.Name,
		Namespace:    obj.Metadata.Namespace,
		Kind:         ownerRef.Kind,
		ResourceName: ownerRef.Name,
		TTL:          &ttl,
	}

	// Parse creation timestamp - prefer metadata.creationTimestamp, fall back to report.updateTimestamp
	// If neither exists, use file modification time
	var creationTime time.Time
	if obj.Metadata.CreationTimestamp != "" {
		t, err := time.Parse(time.RFC3339, obj.Metadata.CreationTimestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse creationTimestamp: %w", err)
		}
		creationTime = t
	} else if obj.Report.UpdateTimestamp != "" {
		t, err := time.Parse(time.RFC3339, obj.Report.UpdateTimestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updateTimestamp: %w", err)
		}
		creationTime = t
	} else {
		// Fall back to file modification time
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat file: %w", err)
		}
		creationTime = fileInfo.ModTime()
	}
	metadata.CreationTimestamp = creationTime

	return metadata, nil
}

// shouldDeleteReport determines if a report should be deleted and returns the reason.
// Note: metadata.TTL is guaranteed to be non-nil by parseReportFile.
func (r *TTLOrphanedReportCleanupReconciler) shouldDeleteReport(ctx context.Context, metadata *reportMetadata) (bool, string) {
	// Check if TTL has expired
	ttlExpired, _ := utils.IsTTLExpired(*metadata.TTL, metadata.CreationTimestamp, r.Clock)
	if !ttlExpired {
		return false, "TTL not expired"
	}

	// Check if resource still exists
	exists, err := r.resourceExists(ctx, metadata.Kind, metadata.Namespace, metadata.ResourceName)
	if err != nil {
		r.Error(err, "Failed to check resource existence",
			"kind", metadata.Kind,
			"name", metadata.ResourceName,
			"namespace", metadata.Namespace)
		return false, "error checking resource existence"
	}

	if exists {
		return false, "resource still exists"
	}

	return true, "TTL expired and resource deleted"
}

// resourceExists checks if a Kubernetes resource still exists
func (r *TTLOrphanedReportCleanupReconciler) resourceExists(ctx context.Context, kind, namespace, name string) (bool, error) {
	var obj client.Object
	var namespacedName types.NamespacedName

	// Create the appropriate object type based on kind
	switch kind {
	case "Pod":
		obj = &corev1.Pod{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "ReplicaSet":
		obj = &appsv1.ReplicaSet{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "Deployment":
		obj = &appsv1.Deployment{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "StatefulSet":
		obj = &appsv1.StatefulSet{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "DaemonSet":
		obj = &appsv1.DaemonSet{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "CronJob":
		obj = &batchv1.CronJob{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "Job":
		obj = &batchv1.Job{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "ReplicationController":
		obj = &corev1.ReplicationController{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "Service":
		obj = &corev1.Service{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "Node":
		obj = &corev1.Node{}
		namespacedName = types.NamespacedName{Name: name}
	case "Role":
		obj = &rbacv1.Role{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "RoleBinding":
		obj = &rbacv1.RoleBinding{}
		namespacedName = types.NamespacedName{Namespace: namespace, Name: name}
	case "ClusterRole":
		obj = &rbacv1.ClusterRole{}
		namespacedName = types.NamespacedName{Name: name}
	case "ClusterRoleBinding":
		obj = &rbacv1.ClusterRoleBinding{}
		namespacedName = types.NamespacedName{Name: name}
	default:
		return false, fmt.Errorf("unsupported resource kind: %s", kind)
	}

	err := r.Get(ctx, namespacedName, obj)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
