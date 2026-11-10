"""App tests using streamlit.testing.v1.AppTest."""
import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

def test_app_loads():
    """Test that the Streamlit app loads without exception."""
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../app/app.py")
    at.run(timeout=30)
    assert not at.exception, f"App raised exception: {at.exception}"

def test_example_buttons_fill_box():
    """Test that example buttons fill the text box."""
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../app/app.py")
    at.run(timeout=30)
    
    # Check initial state - text_input value is in the widget state
    # Find the text_input widget
    text_input = at.text_input[0]
    assert text_input.value == ""
    
    # Click legitimate example button (first button after text_input)
    at.button[0].click().run(timeout=10)
    # Check the text_input value was updated
    at.run(timeout=10)
    assert at.text_input[0].value == "https://www.google.com/search?q=python"
    
    # Click phishing example button (second button)
    at.button[1].click().run(timeout=10)
    at.run(timeout=10)
    assert at.text_input[0].value == "https://secure-login.paypal.verify-update.tk/login.php"

def test_paypal_url_shows_verdict():
    """Test that a PayPal-style URL shows a phishing verdict."""
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../app/app.py")
    at.run(timeout=30)
    
    # Enter a phishing-like URL
    at.text_input[0].input("http://paypal-secure-login-verify.xyz").run(timeout=10)
    
    # Click Check URL (third button - index 2)
    at.button[2].click().run(timeout=10)
    
    # Check that result shows phishing - look for error or warning elements
    # The app shows error for phishing, warning for platform phishing
    has_phishing_msg = False
    for el in at.get("error") + at.get("warning"):
        if "Phishing" in str(el.value) or "phishing" in str(el.value).lower():
            has_phishing_msg = True
            break
    assert has_phishing_msg, f"Expected phishing detection message, got: {at.get('error') + at.get('warning')}"

def test_empty_input_shows_friendly_message():
    """Test that empty input shows a friendly message or does nothing."""
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../app/app.py")
    at.run(timeout=30)
    
    # Click Check URL with empty input
    at.text_input[0].input("").run(timeout=10)
    at.button[2].click().run(timeout=10)
    
    # Should not crash - no exception
    assert not at.exception, f"App raised exception on empty input: {at.exception}"

def test_malformed_input_no_crash():
    """Test that malformed input never crashes."""
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../app/app.py")
    at.run(timeout=30)
    
    # Test various malformed inputs
    test_inputs = [
        "not a url",
        "http://",
        "://missing-scheme.com",
        "http://example.com/path with spaces",
        "x" * 3000,  # very long
    ]
    
    for test_input in test_inputs:
        at.text_input[0].input(test_input).run(timeout=10)
        at.button[2].click().run(timeout=10)
        assert not at.exception, f"App crashed on input: {test_input[:50]}"