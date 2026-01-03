"""Tests for sb_validator executable"""
import subprocess
import os
import pytest
import time
import signal
import tempfile

@pytest.fixture(scope="session", autouse=True)
def build_project():
    """Build the project before running tests (setup)"""
    project_root = os.path.join(os.path.dirname(__file__), "..")
    
    # Run make to build the project
    result = subprocess.run(
        ["make"],
        cwd=project_root,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        pytest.fail(f"Make build failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")
    
    yield  # Run all tests
    
    # Cleanup: run make clean after all tests
    result = subprocess.run(
        ["make", "clean"],
        cwd=project_root,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Warning: Make clean failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")


class TestSbValidator:
    """Test suite for sb_validator"""
    
    @pytest.fixture(scope="class")
    def validator_path(self):
        """Get path to the compiled sb_validator executable"""
        # Look for 'sb_validator' as per your logs
        path = os.path.join(os.path.dirname(__file__), "..", "bin", "sb_validator")
        if not os.path.exists(path):
            path = os.path.join(os.path.dirname(__file__), "..", "sb_validator")
        
        # Fallback to sandbox_validator if sb_validator not found (for compatibility)
        if not os.path.exists(path):
             path = os.path.join(os.path.dirname(__file__), "..", "sandbox_validator")
             
        return os.path.abspath(path)
    
    @pytest.fixture(scope="class")
    def wait_helper_path(self):
        """Get path to the wait_helper executable"""
        path = os.path.join(os.path.dirname(__file__), "..", "bin", "wait_helper")
        if not os.path.exists(path):
            pytest.fail(f"wait_helper not found at {path}. Please ensure it's built with: make")
        return os.path.abspath(path)
    
    @pytest.fixture(scope="class")
    def template_profile_path(self):
        """Get path to the sandbox profile"""
        path = os.path.join(os.path.dirname(__file__), "template_profile.sb")
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("(version 1)\n(allow default)\n")
        return path

    # --- Helper Method to keep tests clean and human-friendly ---

    def run_validation(self, validator_bin, helper_bin, sb_rule, op, filter_type, filter_value):
        """
        1. Creates a temporary profile with the given 'sb_rule'.
        2. Starts 'wait_helper' inside that sandbox.
        3. Runs 'sb_validator' against it.
        4. Returns the stdout/stderr for assertion.
        """
        # Define the profile content
        profile_content = f"(version 1)\n(allow default)\n{sb_rule}"
        
        # Write profile to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sb', delete=False) as tmp:
            tmp.write(profile_content)
            profile_path = tmp.name

        process = None
        output = ""
        
        try:
            # Start the sandboxed process
            cmd = ["sandbox-exec", "-f", profile_path, helper_bin]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(0.5) # Give it time to initialize

            # Check if it crashed immediately
            if process.poll() is not None:
                _, stderr = process.communicate()
                return f"Process failed to start. Error: {stderr}"

            # Get the PID (sandbox-exec performs execve, so pid is the same)
            pid = process.pid

            # Run the validator
            # ./sb_validator <pid> <operation> <filter_type> <value>
            val_cmd = [validator_bin, str(pid), op, filter_type, filter_value]
            result = subprocess.run(val_cmd, capture_output=True, text=True)
            output = result.stdout + result.stderr

        finally:
            # Cleanup process
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except:
                    process.kill()
            
            # Cleanup temp file
            if os.path.exists(profile_path):
                os.remove(profile_path)
                
        return output

    # --- Basic Checks ---

    def test_executable_exists(self, validator_path):
        """Test that sb_validator executable exists"""
        assert os.path.exists(validator_path), f"Executable not found at {validator_path}"
    
    def test_run_without_args(self, validator_path):
        """Test running sb_validator without arguments"""
        result = subprocess.run([validator_path], capture_output=True, text=True)
        assert "Usage:" in (result.stdout + result.stderr)

    # --- Your Original Test ---

    def test_sandbox_exec_with_wait_helper(self, template_profile_path, wait_helper_path):
        """Test running wait_helper in sandbox and verify process management (Legacy Test)"""
        test_dir = os.path.dirname(__file__)
        original_cwd = os.getcwd()
        
        try:
            os.chdir(test_dir)
            cmd = ["sandbox-exec", "-f", template_profile_path, wait_helper_path]
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(1)
            
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(f"Process exited early. stdout: {stdout}, stderr: {stderr}")
            
            result = subprocess.run(
                ["pgrep", "-f", "wait_helper"], capture_output=True, text=True, timeout=5
            )
            pids = [p for p in result.stdout.strip().split("\n") if p]
            assert len(pids) > 0, f"No wait_helper process found. stderr: {result.stderr}"
            
            os.kill(int(pids[-1]), signal.SIGTERM)
            process.wait(timeout=5)
            
        finally:
            os.chdir(original_cwd)

    # --- Specific Filter Tests (Based on your documentation) ---

    def test_filter_path(self, validator_path, wait_helper_path):
        """
        SANDBOX_FILTER_PATH (1)
        Checks access to a specific file path.
        """
        rule = '(deny file-read* (literal "/private/etc/passwd"))'
        
        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="file-read*", 
            filter_type="PATH", 
            filter_value="/private/etc/passwd"
        )
        print(f"PATH (Denied) Output: {output.strip()}")
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="file-read*", 
            filter_type="PATH", 
            filter_value="/private/etc/hosts"
        )
        print(f"PATH (Allowed) Output: {output.strip()}")
        assert "[ALLOWED]" in output

    def test_filter_global_name(self, validator_path, wait_helper_path):
        """
        GLOBAL_NAME (2)
        Checks permission to look up a global Mach service.
        """
        rule = '(deny mach-lookup (global-name "com.apple.replayd"))'
        
        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup", 
            filter_type="GLOBAL_NAME", 
            filter_value="com.apple.replayd"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup", 
            filter_type="GLOBAL_NAME", 
            filter_value="com.apple.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_local_name(self, validator_path, wait_helper_path):
        """
        LOCAL_NAME (3)
        Checks permission for a local/user Mach service.
        """
        rule = '(deny mach-lookup (local-name "com.apple.CFPasteboardClient"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup",
            filter_type="LOCAL_NAME",
            filter_value="com.apple.CFPasteboardClient"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup",
            filter_type="LOCAL_NAME",
            filter_value="com.apple.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_appleevent(self, validator_path, wait_helper_path):
        """
        APPLEEVENT_DESTINATION (4)
        Checks permission to send AppleEvents to a target bundle ID.
        """
        rule = '(deny appleevent-send (appleevent-destination "com.apple.Finder"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="appleevent-send",
            filter_type="APPLEEVENT_DESTINATION",
            filter_value="com.apple.Finder"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="appleevent-send",
            filter_type="APPLEEVENT_DESTINATION",
            filter_value="com.apple.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_right_name(self, validator_path, wait_helper_path):
        """
        RIGHT_NAME (5)
        Checks if the process can obtain a specific authorization right.
        """
        rule = '(deny authorization-right-obtain (right-name "system.hdd.smart"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="authorization-right-obtain",
            filter_type="RIGHT_NAME",
            filter_value="system.hdd.smart"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="authorization-right-obtain",
            filter_type="RIGHT_NAME",
            filter_value="system.hdd.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_preference_domain(self, validator_path, wait_helper_path):
        """
        PREFERENCE_DOMAIN (6)
        Identifies which specific preference plist the process may read or write.
        """
        rule = '(deny user-preference-read (preference-domain "com.apple.AppKit.TextFavorites"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="user-preference-read",
            filter_type="PREFERENCE_DOMAIN",
            filter_value="com.apple.AppKit.TextFavorites"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="user-preference-read",
            filter_type="PREFERENCE_DOMAIN",
            filter_value="com.apple.AppKit.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_kext_bundle_id(self, validator_path, wait_helper_path):
        """
        KEXT_BUNDLE_ID (7)
        Check if process has right to load/unload/query Kernel Extension.
        """
        rule = '(deny system-kext-load (kext-bundle-id "com.apple.filesystems.smbfs"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="system-kext-load",
            filter_type="KEXT_BUNDLE_ID",
            filter_value="com.apple.filesystems.smbfs"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="system-kext-load",
            filter_type="KEXT_BUNDLE_ID",
            filter_value="com.apple.filesystems.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_info_type(self, validator_path, wait_helper_path):
        """
        INFO_TYPE (8)
        Checks access to system information queries (system-info operation).
        """
        rule = '(deny system-info (info-type "net.link.addr"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="system-info",
            filter_type="INFO_TYPE",
            filter_value="net.link.addr"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="system-info",
            filter_type="INFO_TYPE",
            filter_value="crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_notification_type(self, validator_path, wait_helper_path):
        """
        NOTIFICATION (9)
        Checks permission to post distributed notifications with a specific name.
        """
        rule = '(deny distributed-notification-post (notification-name "com.apple.example.notification"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="distributed-notification-post",
            filter_type="NOTIFICATION",
            filter_value="com.apple.example.notification"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="distributed-notification-post",
            filter_type="NOTIFICATION",
            filter_value="com.apple.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_xpc_service_name(self, validator_path, wait_helper_path):
        """
        XPC_SERVICE_NAME (12)
        Checks if the process can perform operations on the XPC service.
        Note: sandbox-exec does not handle xpc-message-send operation (Tahoe 26.0),
        so we use mach-lookup with xpc-service-name instead.
        """
        rule = '(deny mach-lookup (xpc-service-name "com.apple.WebKit.Networking"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup",
            filter_type="XPC_SERVICE_NAME",
            filter_value="com.apple.WebKit.Networking"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="mach-lookup",
            filter_type="XPC_SERVICE_NAME",
            filter_value="com.apple.crimson"
        )
        assert "[ALLOWED]" in output

    def test_filter_nvram_variable(self, validator_path, wait_helper_path):
        """
        NVRAM_VARIABLE (15)
        Checks the name of the NVRAM variable.
        Used with 'nvram-get', 'nvram-set', 'nvram-delete' operations.
        """
        rule = '(deny nvram-get (nvram-variable "boot-args"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="nvram-get",
            filter_type="NVRAM_VARIABLE",
            filter_value="boot-args"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="nvram-get",
            filter_type="NVRAM_VARIABLE",
            filter_value="csr-active-config"
        )
        assert "[ALLOWED]" in output

    def test_filter_posix_ipc_name(self, validator_path, wait_helper_path):
        """
        POSIX_IPC_NAME (17)
        Checks the name of POSIX Semaphores or Shared Memory.
        Used with 'ipc-posix-*' operations.
        """
        rule = '(deny ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))'

        # Case 1: Denied
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="ipc-posix-shm-read-data",
            filter_type="POSIX_IPC_NAME",
            filter_value="apple.shm.notification_center"
        )
        assert "[DENIED]" in output

        # Case 2: Allowed
        output = self.run_validation(
            validator_path, wait_helper_path, rule,
            op="ipc-posix-shm-read-data",
            filter_type="POSIX_IPC_NAME",
            filter_value="test_shm"
        )
        assert "[ALLOWED]" in output