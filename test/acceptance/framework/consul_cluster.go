package framework

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/gruntwork-cli/collections"
	"github.com/gruntwork-io/terratest/modules/files"
	ttesting "github.com/gruntwork-io/terratest/modules/testing"

	"github.com/gruntwork-io/gruntwork-cli/errors"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/hashicorp/consul-helm/test/acceptance/helpers"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/freeport"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The path to the helm chart.
// Note: this will need to be changed if this file is moved.
const helmChartPath = "../../../.."

// Cluster represents a consul cluster object
type Cluster interface {
	Create(t *testing.T)
	Destroy(t *testing.T)
	Upgrade(t *testing.T)
	SetupConsulClient(t *testing.T, secure bool) *api.Client
}

// HelmCluster implements Cluster and uses Helm
// to create, destroy, and upgrade consul
type HelmCluster struct {
	helmOptions      *helm.Options
	releaseName      string
	kubernetesClient kubernetes.Interface
	cleanupOnFailure bool
}

func NewHelmCluster(
	t *testing.T,
	helmValues map[string]string,
	ctx TestContext,
	cfg *TestConfig,
	releaseName string) Cluster {

	// Deploy single-server cluster by default unless helmValues overwrites that
	values := map[string]string{
		"server.replicas":        "1",
		"server.bootstrapExpect": "1",
	}
	valuesFromConfig := cfg.HelmValuesFromConfig()

	// Merge all helm values
	mergeMaps(values, valuesFromConfig)
	mergeMaps(values, helmValues)

	opts := &helm.Options{
		SetValues:      values,
		KubectlOptions: ctx.KubectlOptions(),
		Logger:         logger.TestingT,
	}
	return &HelmCluster{
		helmOptions:      opts,
		releaseName:      releaseName,
		kubernetesClient: ctx.KubernetesClient(t),
		cleanupOnFailure: cfg.CleanupOnFailure,
	}
}

func (h *HelmCluster) Create(t *testing.T) {
	t.Helper()

	// Make sure we delete the cluster if we receive an interrupt signal and
	// register cleanup so that we delete the cluster when test finishes.
	helpers.Cleanup(t, func() {
		if !t.Failed() || h.cleanupOnFailure {
			h.Destroy(t)
		} else {
			t.Log("skipping resource cleanup")
		}
	})

	// Fail if there are any existing installations of the Helm chart.
	h.checkForPriorInstallations(t)

	install(t, h.helmOptions, helmChartPath, h.releaseName)

	helpers.WaitForAllPodsToBeReady(t, h.kubernetesClient, h.helmOptions.KubectlOptions.Namespace, fmt.Sprintf("release=%s", h.releaseName))
}

func install(t ttesting.TestingT, options *helm.Options, chart string, releaseName string) error {
	// If the chart refers to a path, convert to absolute path. Otherwise, pass straight through as it may be a remote
	// chart.
	if files.FileExists(chart) {
		absChartDir, err := filepath.Abs(chart)
		if err != nil {
			return errors.WithStackTrace(err)
		}
		chart = absChartDir
	}

	// Now call out to helm install to install the charts with the provided options
	// Declare err here so that we can update args later
	var err error
	args := []string{}
	args = append(args, getNamespaceArgs(options)...)
	if options.Version != "" {
		args = append(args, "--version", options.Version)
	}
	args, err = getValuesArgsE(t, options, args...)
	if err != nil {
		return err
	}
	args = append(args, "--timeout=15m", releaseName, chart)
	_, err = helm.RunHelmCommandAndGetOutputE(t, options, "install", args...)
	return err
}

func getValuesArgsE(t ttesting.TestingT, options *helm.Options, args ...string) ([]string, error) {
	args = append(args, formatSetValuesAsArgs(options.SetValues, "--set")...)
	args = append(args, formatSetValuesAsArgs(options.SetStrValues, "--set-string")...)

	valuesFilesArgs, err := formatValuesFilesAsArgsE(t, options.ValuesFiles)
	if err != nil {
		return args, errors.WithStackTrace(err)
	}
	args = append(args, valuesFilesArgs...)

	setFilesArgs, err := formatSetFilesAsArgsE(t, options.SetFiles)
	if err != nil {
		return args, errors.WithStackTrace(err)
	}
	args = append(args, setFilesArgs...)
	return args, nil
}

func formatSetValuesAsArgs(setValues map[string]string, flag string) []string {
	args := []string{}

	// To make it easier to test, go through the keys in sorted order
	keys := collections.Keys(setValues)
	for _, key := range keys {
		value := setValues[key]
		argValue := fmt.Sprintf("%s=%s", key, value)
		args = append(args, flag, argValue)
	}

	return args
}

// formatSetFilesAsArgs formats the given list of keys and file paths as command line args for helm to set from file
// (e.g of the format --set-file key=path). This will fail the test if one of the paths do not exist or the absolute
// path can not be determined.
func formatSetFilesAsArgs(t ttesting.TestingT, setFiles map[string]string) []string {
	args, err := formatSetFilesAsArgsE(t, setFiles)
	require.NoError(t, err)
	return args
}

// formatSetFilesAsArgsE formats the given list of keys and file paths as command line args for helm to set from file
// (e.g of the format --set-file key=path)
func formatSetFilesAsArgsE(t ttesting.TestingT, setFiles map[string]string) ([]string, error) {
	args := []string{}

	// To make it easier to test, go through the keys in sorted order
	keys := collections.Keys(setFiles)
	for _, key := range keys {
		setFilePath := setFiles[key]
		// Pass through filepath.Abs to clean the path, and then make sure this file exists
		absSetFilePath, err := filepath.Abs(setFilePath)
		if err != nil {
			return args, errors.WithStackTrace(err)
		}
		if !files.FileExists(absSetFilePath) {
			return args, errors.WithStackTrace(helm.SetFileNotFoundError{setFilePath})
		}
		argValue := fmt.Sprintf("%s=%s", key, absSetFilePath)
		args = append(args, "--set-file", argValue)
	}

	return args, nil
}

// formatValuesFilesAsArgs formats the given list of values file paths as command line args for helm (e.g of the format
// -f path). This will fail the test if one of the paths do not exist or the absolute path can not be determined.
func formatValuesFilesAsArgs(t ttesting.TestingT, valuesFiles []string) []string {
	args, err := formatValuesFilesAsArgsE(t, valuesFiles)
	require.NoError(t, err)
	return args
}

// formatValuesFilesAsArgsE formats the given list of values file paths as command line args for helm (e.g of the format
// -f path). This will error if the file does not exist.
func formatValuesFilesAsArgsE(t ttesting.TestingT, valuesFiles []string) ([]string, error) {
	args := []string{}

	for _, valuesFilePath := range valuesFiles {
		// Pass through filepath.Abs to clean the path, and then make sure this file exists
		absValuesFilePath, err := filepath.Abs(valuesFilePath)
		if err != nil {
			return args, errors.WithStackTrace(err)
		}
		if !files.FileExists(absValuesFilePath) {
			return args, errors.WithStackTrace(helm.ValuesFileNotFoundError{valuesFilePath})
		}
		args = append(args, "-f", absValuesFilePath)
	}

	return args, nil
}

func getNamespaceArgs(options *helm.Options) []string {
	if options.KubectlOptions != nil && options.KubectlOptions.Namespace != "" {
		return []string{"--namespace", options.KubectlOptions.Namespace}
	}
	return []string{}
}

func (h *HelmCluster) Destroy(t *testing.T) {
	t.Helper()

	helm.Delete(t, h.helmOptions, h.releaseName, false)

	// delete PVCs
	h.kubernetesClient.CoreV1().PersistentVolumeClaims(h.helmOptions.KubectlOptions.Namespace).DeleteCollection(&metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "release=" + h.releaseName})

	// delete any secrets that have h.releaseName in their name
	secrets, err := h.kubernetesClient.CoreV1().Secrets(h.helmOptions.KubectlOptions.Namespace).List(metav1.ListOptions{})
	require.NoError(t, err)
	for _, secret := range secrets.Items {
		if strings.Contains(secret.Name, h.releaseName) {
			err := h.kubernetesClient.CoreV1().Secrets(h.helmOptions.KubectlOptions.Namespace).Delete(secret.Name, nil)
			require.NoError(t, err)
		}
	}

	// delete any serviceaccounts that have h.releaseName in their name
	sas, err := h.kubernetesClient.CoreV1().ServiceAccounts(h.helmOptions.KubectlOptions.Namespace).List(metav1.ListOptions{})
	require.NoError(t, err)
	for _, sa := range sas.Items {
		if strings.Contains(sa.Name, h.releaseName) {
			err := h.kubernetesClient.CoreV1().ServiceAccounts(h.helmOptions.KubectlOptions.Namespace).Delete(sa.Name, nil)
			require.NoError(t, err)
		}
	}
}

func (h *HelmCluster) Upgrade(t *testing.T) {
	helm.Upgrade(t, h.helmOptions, helmChartPath, h.releaseName)
	helpers.WaitForAllPodsToBeReady(t, h.kubernetesClient, h.helmOptions.KubectlOptions.Namespace, fmt.Sprintf("release=%s", h.releaseName))
}

func (h *HelmCluster) SetupConsulClient(t *testing.T, secure bool) *api.Client {
	t.Helper()

	namespace := h.helmOptions.KubectlOptions.Namespace
	config := api.DefaultConfig()
	localPort := freeport.MustTake(1)[0]
	remotePort := 8500 // use non-secure by default

	if secure {
		// overwrite remote port to HTTPS
		remotePort = 8501

		// get the CA
		caSecret, err := h.kubernetesClient.CoreV1().Secrets(namespace).Get(h.releaseName+"-consul-ca-cert", metav1.GetOptions{})
		require.NoError(t, err)
		caFile, err := ioutil.TempFile("", "")
		require.NoError(t, err)
		helpers.Cleanup(t, func() {
			require.NoError(t, os.Remove(caFile.Name()))
		})

		if caContents, ok := caSecret.Data["tls.crt"]; ok {
			_, err := caFile.Write(caContents)
			require.NoError(t, err)
		}

		// get the ACL token
		aclSecret, err := h.kubernetesClient.CoreV1().Secrets(namespace).Get(h.releaseName+"-consul-bootstrap-acl-token", metav1.GetOptions{})
		require.NoError(t, err)

		config.TLSConfig.CAFile = caFile.Name()
		config.Token = string(aclSecret.Data["token"])
		config.Scheme = "https"
	}

	tunnel := k8s.NewTunnel(h.helmOptions.KubectlOptions, k8s.ResourceTypePod, fmt.Sprintf("%s-consul-server-0", h.releaseName), localPort, remotePort)
	tunnel.ForwardPort(t)

	t.Cleanup(func() {
		tunnel.Close()
	})

	config.Address = fmt.Sprintf("127.0.0.1:%d", localPort)
	consulClient, err := api.NewClient(config)
	require.NoError(t, err)

	return consulClient
}

// checkForPriorInstallations checks if there is an existing Helm release
// for this Helm chart already installed. If there is, it fails the tests.
func (h *HelmCluster) checkForPriorInstallations(t *testing.T) {
	t.Helper()

	// check if there's an existing cluster and fail if there is
	output, err := helm.RunHelmCommandAndGetOutputE(t, h.helmOptions, "list", "--output", "json")
	require.NoError(t, err)

	var installedReleases []map[string]string

	err = json.Unmarshal([]byte(output), &installedReleases)
	require.NoError(t, err)

	for _, r := range installedReleases {
		require.NotContains(t, r["chart"], "consul", fmt.Sprintf("detected an existing installation of Consul %s", r["chart"]))
	}
}

// mergeValues will merge the values in b with values in a and save in a.
// If there are conflicts, the values in b will overwrite the values in a.
func mergeMaps(a, b map[string]string) {
	for k, v := range b {
		a[k] = v
	}
}
