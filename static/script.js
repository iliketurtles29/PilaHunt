const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');
const passwordInput = document.getElementById('passwordInput');
const confirmPasswordInput = document.getElementById('confirmPasswordInput');
const passwordError = document.getElementById('passwordError');
const signupButton = document.getElementById('signupButton');

registerBtn.addEventListener('click', () => {
    container.classList.add("active");
});

loginBtn.addEventListener('click', () => {
    container.classList.remove("active");
});

confirmPasswordInput.addEventListener('input', () => {
    if (passwordInput.value !== confirmPasswordInput.value) {
        confirmPasswordInput.classList.add('error');
        passwordError.innerText = "Password don't match";
        signupButton.disabled = true;
    } else {
        confirmPasswordInput.classList.remove('error');
        passwordError.innerText = "";
        signupButton.disabled = false;
    }
});