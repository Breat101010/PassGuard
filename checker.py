import re

def check_password_strength(password):
    """
    Checks the strength of a password based on several criteria.
    """
    score = 0
    feedback = []

    # Criteria Checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Password should contain numbers.")

    if re.search(r"[@$!%*#?&]", password):
        score += 1
    else:
        feedback.append("Password should contain special characters (@$!%*#?&).")

    # Final Evaluation
    if score == 5:
        return "Very Strong", feedback
    elif score >= 3:
        return "Medium", feedback
    else:
        return "Weak", feedback

if __name__ == "__main__":
    password = input("Enter a password to check its strength: ")
    strength, feedback = check_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    if feedback:
        print("Feedback:")
        for item in feedback:
            print(f"- {item}")
    else:
        print("Your password meets all criteria.")