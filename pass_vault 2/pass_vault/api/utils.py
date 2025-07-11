import secrets
import string
from typing import List

def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_numbers: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """Generates a secure random password based on specified criteria."""
    
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    
    characters = ""
    required_chars = []
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI"
        lowercase = lowercase.translate(str.maketrans("", "", ambiguous))
        uppercase = uppercase.translate(str.maketrans("", "", ambiguous))
        numbers = numbers.translate(str.maketrans("", "", ambiguous))
    
    # Build character set and ensure at least one character from each selected type
    if include_lowercase:
        characters += lowercase
        required_chars.append(secrets.choice(lowercase))
    
    if include_uppercase:
        characters += uppercase
        required_chars.append(secrets.choice(uppercase))
    
    if include_numbers:
        characters += numbers
        required_chars.append(secrets.choice(numbers))
    
    if include_symbols:
        characters += symbols
        required_chars.append(secrets.choice(symbols))
    
    if not characters:
        raise ValueError("At least one character type must be selected")
    
    # Generate remaining characters
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(characters) for _ in range(remaining_length)]
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password_chars)
    
    return "".join(password_chars)

def validate_password_strength(password: str) -> dict:
    """Validates password strength and returns feedback."""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    if len(password) >= 12:
        score += 1
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password should contain numbers")
    
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1
    else:
        feedback.append("Password should contain special characters")
    
    # Check for common patterns
    if password.lower() in ["password", "123456", "qwerty", "abc123"]:
        score = 0
        feedback.append("Password is too common")
    
    strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    strength = strength_levels[min(score, len(strength_levels) - 1)]
    
    return {
        "score": score,
        "max_score": 6,
        "strength": strength,
        "feedback": feedback,
        "is_strong": score >= 4
    }

def mask_password(password: str, visible_chars: int = 3) -> str:
    """Masks a password showing only first few characters."""
    if len(password) <= visible_chars:
        return "*" * len(password)
    
    return password[:visible_chars] + "*" * (len(password) - visible_chars)

def sanitize_filename(filename: str) -> str:
    """Sanitizes a filename for safe storage."""
    import re
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    filename = filename.strip('. ')
    return filename if filename else "unnamed" 