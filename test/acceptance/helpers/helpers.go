package helpers

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RandomName generates a random string with a 'test-' prefix.
func RandomName() string {
	return fmt.Sprintf("test-%s", strings.ToLower(random.UniqueId()))
}

// WaitForAllPodsToBeReady waits until all pods with the provided podLabelSelector
// are in the ready status. It checks every 5 seconds for a total of 20 tries.
// If there is at least one container in a pod that isn't ready after that,
// it fails the test.
func WaitForAllPodsToBeReady(t *testing.T, client kubernetes.Interface, namespace, podLabelSelector string) {
	t.Helper()

	counter := &retry.Counter{Count: 20, Wait: 5 * time.Second}
	retry.RunWith(counter, t, func(r *retry.R) {
		pods, err := client.CoreV1().Pods(namespace).List(metav1.ListOptions{LabelSelector: podLabelSelector})
		require.NoError(r, err)
		var numNotReadyContainers int
		var totalNumContainers int
		for _, pod := range pods.Items {
			if len(pod.Status.ContainerStatuses) == 0 {
				r.Errorf("pod %s is pending", pod.Name)
			}
			for _, contStatus := range pod.Status.InitContainerStatuses {
				totalNumContainers++
				if !contStatus.Ready {
					numNotReadyContainers++
				}
			}
			for _, contStatus := range pod.Status.ContainerStatuses {
				totalNumContainers++
				if !contStatus.Ready {
					numNotReadyContainers++
				}
			}
		}
		if numNotReadyContainers != 0 {
			r.Errorf("%d out of %d containers are ready", totalNumContainers-numNotReadyContainers, totalNumContainers)
		}
	})
}

// Sets up a goroutine that will wait for interrupt signals
// and call cleanup function when it catches it.
func SetupInterruptHandler(cleanup func()) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal. Cleaning up resources.")
		cleanup()
		os.Exit(1)
	}()
}

// Cleanup will both register a cleanup function with t
// and SetupInterruptHandler to make sure resources get cleaned up
// if an interrupt signal is caught.
func Cleanup(t *testing.T, noCleanupOnFailure bool, cleanup func()) {
	// Always clean up when an interrupt signal is caught.
	SetupInterruptHandler(cleanup)

	// If noCleanupOnFailure is set, don't clean up resources if tests fail.
	// We need to wrap the cleanup function because t that is passed in to this function
	// might not have the information on whether the test has failed yet.
	wrappedCleanupFunc := func() {
		if !(noCleanupOnFailure && t.Failed()) {
			t.Logf("cleaning up resources for %s", t.Name())
			cleanup()
		} else {
			t.Log("skipping resource cleanup")
		}
	}

	t.Cleanup(wrappedCleanupFunc)
}

// todo: docs
func WritePodsDebugInfoIfFailed(t *testing.T, client kubernetes.Interface, kubectlOptions *k8s.KubectlOptions, clusterName, debugDirectory, labelSelector string) {
	t.Helper()

	if t.Failed() {
		// Create a directory for the test
		testDebugDirectory := filepath.Join(debugDirectory, t.Name(), clusterName)
		require.NoError(t, os.MkdirAll(testDebugDirectory, 0755))

		t.Logf("dumping logs and pod info for %s to %s", labelSelector, testDebugDirectory)

		pods, err := client.CoreV1().Pods(kubectlOptions.Namespace).List(metav1.ListOptions{LabelSelector: labelSelector})
		require.NoError(t, err)

		for _, pod := range pods.Items {
			// Get logs for each pod, passing the discard logger to make sure secrets aren't printed to test logs.
			logs, err := RunKubectlAndGetOutputWithLoggerE(t, kubectlOptions, logger.Discard, "logs", "--all-containers=true", pod.Name)
			require.NoError(t, err)

			// Write logs to file name <pod.Name>.log
			logFilename := filepath.Join(testDebugDirectory, fmt.Sprintf("%s.log", pod.Name))
			require.NoError(t, ioutil.WriteFile(logFilename, []byte(logs), 0600))

			// Describe pod
			desc, err := RunKubectlAndGetOutputWithLoggerE(t, kubectlOptions, logger.Discard, "describe", "pod", pod.Name)
			require.NoError(t, err)

			// Write pod info to file name <pod.Name>.txt
			descFilename := filepath.Join(testDebugDirectory, fmt.Sprintf("%s.txt", pod.Name))
			require.NoError(t, ioutil.WriteFile(descFilename, []byte(desc), 0600))
		}
	}
}
