const sign_in_btn = document.querySelector("#sign-in-btn");
const sign_up_btn = document.querySelector("#sign-up-btn");
const container = document.querySelector(".container");

sign_up_btn.addEventListener('click', () =>{
    container.classList.add("sign-up-mode");
});

sign_in_btn.addEventListener('click', () =>{
    container.classList.remove("sign-up-mode");
});

const passwordInput = document.getElementById('passwordInput');
const confirmPasswordInput = document.getElementById('confirmPasswordInput');
const passwordError = document.getElementById('passwordError');
const signupButton = document.getElementById('signupButton');

confirmPasswordInput.addEventListener('input', () => {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // Check if passwords match
    if (password !== confirmPassword) {
        confirmPasswordInput.classList.add('error');
        passwordError.innerText = "Passwords don't match";
        signupButton.disabled = true;
    } else {
        confirmPasswordInput.classList.remove('error');
        passwordError.innerText = "";
        signupButton.disabled = false;

        // Check password strength
        const regex = /^(?=.*[!@#$%^&*()_+}{:;'?/>,.<,])(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$/;
        if (!regex.test(password)) {
            passwordInput.classList.add('error');
            passwordError.innerText = "Password should be at least 8 characters long and contain at least one special character, one uppercase letter, one lowercase letter, and one digit.";
            signupButton.disabled = true;
        } else {
            passwordInput.classList.remove('error');
            passwordError.innerText = "";
            signupButton.disabled = false;
        }
    }
});