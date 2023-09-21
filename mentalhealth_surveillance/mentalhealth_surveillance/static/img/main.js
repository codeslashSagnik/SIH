const text = "A group video calling platform made just for you!";
    let index = 0;

    function typeEffect() {
        if (index < text.length) {
            document.getElementById("typing-effect").textContent += text.charAt(index);
            index++;
            setTimeout(typeEffect, 100); // Adjust the 100 if you want it faster or slower
        } else {
            // Remove blinking cursor after typing is done
            const typingElement = document.getElementById("typing-effect");
            typingElement.classList.remove("cursor");
        }
    }

    window.addEventListener("DOMContentLoaded", typeEffect); 