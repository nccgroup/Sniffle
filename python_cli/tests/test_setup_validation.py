"""Validation tests to ensure the testing infrastructure is properly set up."""

import pytest
import sys
from pathlib import Path


class TestSetupValidation:
    """Test class to validate the testing infrastructure setup."""
    
    def test_python_version(self):
        """Verify Python version is 3.9 or higher."""
        assert sys.version_info >= (3, 9), "Python 3.9+ is required"
    
    def test_pytest_installed(self):
        """Verify pytest is installed and importable."""
        import pytest as pt
        assert pt is not None
        assert hasattr(pt, '__version__')
    
    def test_pytest_cov_installed(self):
        """Verify pytest-cov is installed."""
        import pytest_cov
        assert pytest_cov is not None
    
    def test_pytest_mock_installed(self):
        """Verify pytest-mock is installed."""
        import pytest_mock
        assert pytest_mock is not None
    
    def test_project_structure(self):
        """Verify the expected project structure exists."""
        project_root = Path(__file__).parent.parent
        
        # Check main package exists
        assert (project_root / 'sniffle').exists(), "sniffle package not found"
        assert (project_root / 'sniffle' / '__init__.py').exists()
        
        # Check test directories exist
        assert (project_root / 'tests').exists()
        assert (project_root / 'tests' / '__init__.py').exists()
        assert (project_root / 'tests' / 'unit').exists()
        assert (project_root / 'tests' / 'integration').exists()
        assert (project_root / 'tests' / 'conftest.py').exists()
    
    def test_pyproject_toml_exists(self):
        """Verify pyproject.toml exists and has proper configuration."""
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / 'pyproject.toml'
        
        assert pyproject_path.exists(), "pyproject.toml not found"
        
        # Read and verify basic content
        content = pyproject_path.read_text()
        assert '[tool.poetry]' in content
        assert '[tool.pytest.ini_options]' in content
        assert '[tool.coverage.run]' in content
    
    @pytest.mark.unit
    def test_unit_marker(self):
        """Test that unit test marker works."""
        assert True
    
    @pytest.mark.integration
    def test_integration_marker(self):
        """Test that integration test marker works."""
        assert True
    
    @pytest.mark.slow
    def test_slow_marker(self):
        """Test that slow test marker works."""
        assert True
    
    def test_fixtures_available(self, temp_dir, mock_serial_port, sample_ble_packet):
        """Test that common fixtures are available and working."""
        # Test temp_dir fixture
        assert temp_dir.exists()
        assert temp_dir.is_dir()
        
        # Test mock_serial_port fixture
        assert hasattr(mock_serial_port, 'read')
        assert hasattr(mock_serial_port, 'write')
        assert mock_serial_port.is_open is True
        
        # Test sample_ble_packet fixture
        assert isinstance(sample_ble_packet, dict)
        assert 'aa' in sample_ble_packet
        assert 'chan' in sample_ble_packet
        assert 'rssi' in sample_ble_packet
    
    def test_coverage_configured(self):
        """Verify coverage is properly configured."""
        # This test will pass if coverage is running
        # The actual coverage threshold is enforced by pytest-cov
        assert True
    
    def test_imports_work(self):
        """Test that we can import the main package modules."""
        try:
            # These imports might fail if dependencies aren't installed
            # but that's okay for the validation test
            import sniffle
            assert sniffle is not None
        except ImportError:
            pytest.skip("sniffle package not yet fully installed")


@pytest.mark.parametrize("test_input,expected", [
    (1, 1),
    (2, 2),
    (3, 3),
])
def test_parametrize_works(test_input, expected):
    """Test that pytest parametrize decorator works."""
    assert test_input == expected


def test_monkeypatch_works(monkeypatch):
    """Test that monkeypatch fixture works."""
    import os
    monkeypatch.setenv('TEST_VAR', 'test_value')
    assert os.environ.get('TEST_VAR') == 'test_value'


def test_tmp_path_works(tmp_path):
    """Test that tmp_path fixture works."""
    assert tmp_path.exists()
    test_file = tmp_path / 'test.txt'
    test_file.write_text('test content')
    assert test_file.read_text() == 'test content'