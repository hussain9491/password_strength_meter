import streamlit as st
import re
import string
import math
import time
import zxcvbn
import plotly.graph_objects as go
from typing import Dict, List, Tuple

# Set page config
st.set_page_config(page_title="Advanced Password Strength Meter", page_icon="🔒", layout="wide")

# Add custom CSS
st.markdown("""
<style>
    .password-very-weak { color: #ff0000; font-weight: bold; }
    .password-weak { color: #ff4500; font-weight: bold; }
    .password-medium { color: #ffa500; font-weight: bold; }
    .password-strong { color: #9acd32; font-weight: bold; }
    .password-very-strong { color: #008000; font-weight: bold; }
    .stProgress > div > div > div > div {
        background-color: var(--progress-color, #ff0000);
    }
    .css-1kyxreq {
        justify-content: center;
    }
    .suggestion-box {
        background-color: #f0f2f6;
        border-radius: 5px;
        padding: 10px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Password Analysis Functions
def analyze_entropy(password: str) -> float:
    """Calculate password entropy in bits."""
    if not password:
        return 0
    
    # Calculate character set size
    char_set_size = 0
    if any(c in string.ascii_lowercase for c in password):
        char_set_size += 26
    if any(c in string.ascii_uppercase for c in password):
        char_set_size += 26
    if any(c in string.digits for c in password):
        char_set_size += 10
    if any(c in string.punctuation for c in password):
        char_set_size += len(string.punctuation)
    
    # If we somehow didn't identify any character sets, set a minimum
    if char_set_size == 0:
        char_set_size = 10
        
    # Calculate entropy
    entropy = math.log2(char_set_size) * len(password)
    return entropy

def analyze_character_distribution(password: str) -> Dict[str, int]:
    """Analyze character distribution in password."""
    distribution = {
        'lowercase': sum(1 for c in password if c in string.ascii_lowercase),
        'uppercase': sum(1 for c in password if c in string.ascii_uppercase),
        'digits': sum(1 for c in password if c in string.digits),
        'special': sum(1 for c in password if c in string.punctuation),
        'other': sum(1 for c in password if c not in string.ascii_letters + string.digits + string.punctuation)
    }
    return distribution

def find_patterns(password: str) -> Dict[str, int]:
    """Find common patterns in password."""
    patterns = {
        'sequential_chars': 0,
        'repeated_chars': 0,
        'keyboard_patterns': 0,
        'common_words': 0
    }
    
    # Check for sequential characters
    for i in range(len(password) - 2):
        if (ord(password[i]) + 1 == ord(password[i+1]) and 
            ord(password[i+1]) + 1 == ord(password[i+2])):
            patterns['sequential_chars'] += 1
    
    # Check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            patterns['repeated_chars'] += 1
    
    # Simple keyboard pattern detection (can be expanded)
    keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            pattern = row[i:i+3].lower()
            if pattern in password.lower():
                patterns['keyboard_patterns'] += 1
    
    # List of common words/patterns to check for
    common_words = ["password", "123456", "qwerty", "admin", "welcome", 
                    "login", "abc123", "letmein", "monkey", "football"]
    for word in common_words:
        if word in password.lower():
            patterns['common_words'] += 1
    
    return patterns

def calculate_crack_time(entropy: float) -> Tuple[float, str]:
    """Estimate time to crack the password based on entropy."""
    # Assume 10 billion guesses per second (modern password cracker)
    guesses_per_second = 10000000000
    
    # Calculate number of guesses needed
    guesses = 2 ** entropy
    
    # Calculate time in seconds
    seconds = guesses / guesses_per_second
    
    # Convert to appropriate time unit
    if seconds < 60:
        return seconds, "seconds"
    elif seconds < 3600:
        return seconds / 60, "minutes"
    elif seconds < 86400:
        return seconds / 3600, "hours"
    elif seconds < 31536000:
        return seconds / 86400, "days"
    elif seconds < 31536000 * 100:
        return seconds / 31536000, "years"
    else:
        return seconds / 31536000, "years"

def get_rate_color(score: int) -> str:
    """Get color based on score."""
    colors = {
        0: "#ff0000",  # Very Weak - Red
        1: "#ff4500",  # Weak - Orange Red
        2: "#ffa500",  # Medium - Orange
        3: "#9acd32",  # Strong - Yellow Green
        4: "#008000"   # Very Strong - Green
    }
    return colors.get(score, "#ff0000")

def get_rate_label(score: int) -> str:
    """Get label based on score."""
    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Medium",
        3: "Strong",
        4: "Very Strong"
    }
    return labels.get(score, "Very Weak")

def get_suggestions(password: str, char_distribution: Dict[str, int], patterns: Dict[str, int]) -> List[str]:
    """Get suggestions to improve password strength."""
    suggestions = []
    
    if not password:
        return ["Enter a password to get suggestions"]
    
    if len(password) < 12:
        suggestions.append("Make your password longer (aim for at least 12 characters)")
    
    if char_distribution['lowercase'] == 0:
        suggestions.append("Add lowercase letters")
    
    if char_distribution['uppercase'] == 0:
        suggestions.append("Add uppercase letters")
    
    if char_distribution['digits'] == 0:
        suggestions.append("Add numbers")
    
    if char_distribution['special'] == 0:
        suggestions.append("Add special characters (e.g., @, #, $, %)")
    
    if patterns['sequential_chars'] > 0:
        suggestions.append("Avoid sequential characters (e.g., abc, 123)")
    
    if patterns['repeated_chars'] > 0:
        suggestions.append("Avoid repeated characters (e.g., aaa, 111)")
    
    if patterns['keyboard_patterns'] > 0:
        suggestions.append("Avoid keyboard patterns (e.g., qwerty, asdf)")
    
    if patterns['common_words'] > 0:
        suggestions.append("Avoid common words and patterns")
    
    if len(suggestions) == 0:
        suggestions.append("Your password looks good! Remember to use different passwords for different accounts.")
    
    return suggestions

# Main app
def main():
    st.title("🔒 Advanced Password Strength Meter")
    
    # Password input with toggle for visibility
    col1, col2 = st.columns([4, 1])
    with col1:
        password_visible = col2.checkbox("Show password", value=False)
        if password_visible:
            password = st.text_input("Enter your password:", key="visible_password")
        else:
            password = st.text_input("Enter your password:", type="password", key="hidden_password")
    
    # Add a small delay for visual effect
    if password:
        progress_bar = st.progress(0)
        for i in range(1, 101):
            # Faster progress to make the app feel responsive
            progress_bar.progress(i/100)
            time.sleep(0.005)
        
        # Clear the progress bar after completion
        st.empty()
    
    # Analyze password if provided
    if password:
        # Get zxcvbn score and other metrics
        result = zxcvbn.zxcvbn(password)
        score = result['score']  # 0-4 score
        
        # Custom metrics
        entropy = analyze_entropy(password)
        char_distribution = analyze_character_distribution(password)
        patterns = find_patterns(password)
        crack_time_value, crack_time_unit = calculate_crack_time(entropy)
        
        # Prepare feedback
        color = get_rate_color(score)
        label = get_rate_label(score)
        
        # Create columns for layout
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Display overall strength with colored label
            st.markdown(f"### Password Strength: <span class='password-{label.lower().replace(' ', '-')}'>{label}</span>", unsafe_allow_html=True)
            
            # Display progress bar with color
            st.markdown(f"""
                <style>
                    :root {{
                        --progress-color: {color};
                    }}
                </style>
            """, unsafe_allow_html=True)
            st.progress((score + 1) / 5)
            
            # Estimated crack time
            st.markdown(f"### Estimated time to crack: *{crack_time_value:.2f} {crack_time_unit}*")
            
            # Display zxcvbn feedback
            if result['feedback']['warning']:
                st.warning(result['feedback']['warning'])
            
            # Display suggestions
            suggestions = get_suggestions(password, char_distribution, patterns)
            st.markdown("### Suggestions to improve:")
            for suggestion in suggestions:
                st.markdown(f"<div class='suggestion-box'>🔹 {suggestion}</div>", unsafe_allow_html=True)
        
        with col2:
            # Password composition chart
            labels = ['Lowercase', 'Uppercase', 'Digits', 'Special', 'Other']
            values = [
                char_distribution['lowercase'],
                char_distribution['uppercase'],
                char_distribution['digits'],
                char_distribution['special'],
                char_distribution['other']
            ]
            
            # Filter out zero values
            non_zero_labels = [label for label, value in zip(labels, values) if value > 0]
            non_zero_values = [value for value in values if value > 0]
            
            if sum(values) > 0:  # Only show chart if we have characters
                fig = go.Figure(data=[go.Pie(
                    labels=non_zero_labels,
                    values=non_zero_values,
                    hole=.3,
                    marker_colors=['#4CAF50', '#2196F3', '#FFC107', '#FF5722', '#9C27B0']
                )])
                fig.update_layout(
                    title="Character Composition",
                    height=300,
                    margin=dict(l=10, r=10, t=40, b=10)
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Show detailed metrics
            st.markdown("### Password Details:")
            st.markdown(f"*Length:* {len(password)} characters")
            st.markdown(f"*Entropy:* {entropy:.2f} bits")
            
            # Check for patterns
            pattern_count = sum(patterns.values())
            if pattern_count > 0:
                st.markdown(f"*Patterns detected:* {pattern_count}")
                for pattern_type, count in patterns.items():
                    if count > 0:
                        st.markdown(f"- {pattern_type.replace('_', ' ').title()}: {count}")
    
    # Information about the app
    with st.expander("About this Password Strength Meter"):
        st.markdown("""
        This advanced password strength meter evaluates your password based on multiple factors:
        
        - *Length*: Longer passwords are generally stronger
        - *Character variety*: Using a mix of lowercase, uppercase, numbers, and special characters
        - *Entropy*: A measure of randomness and unpredictability
        - *Common patterns*: Detecting sequential characters, repeated characters, keyboard patterns
        - *Dictionary words*: Checking for common words and passwords
        
        The tool uses the zxcvbn library (developed by Dropbox) for core analysis, supplemented with custom metrics.
        
        *Note*: This tool is for educational purposes only. Always use a password manager for generating and storing strong, unique passwords.
        """)

# Run the app
if __name__ == "__main__":
    main()