/* ============================================
   Pinnacle Wealth Advisors — Main JS
   No external dependencies
   ============================================ */

(function () {
  "use strict";

  /* ----- Mobile Navigation Toggle ----- */
  const hamburger = document.querySelector(".hamburger");
  const navLinks = document.querySelector(".nav-links");

  if (hamburger && navLinks) {
    hamburger.addEventListener("click", function () {
      hamburger.classList.toggle("active");
      navLinks.classList.toggle("open");
    });

    // Close menu when a link is clicked
    navLinks.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        hamburger.classList.remove("active");
        navLinks.classList.remove("open");
      });
    });
  }

  /* ----- Header Scroll Shadow ----- */
  const header = document.querySelector(".site-header");

  function handleScroll() {
    if (!header) return;
    if (window.scrollY > 20) {
      header.classList.add("scrolled");
    } else {
      header.classList.remove("scrolled");
    }
  }

  window.addEventListener("scroll", handleScroll, { passive: true });
  handleScroll();

  /* ----- Smooth Scroll for Anchor Links ----- */
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener("click", function (e) {
      var targetId = this.getAttribute("href");
      if (targetId === "#") return;

      var target = document.querySelector(targetId);
      if (target) {
        e.preventDefault();
        var headerOffset = 90;
        var elementPosition = target.getBoundingClientRect().top + window.pageYOffset;
        var offsetPosition = elementPosition - headerOffset;

        window.scrollTo({
          top: offsetPosition,
          behavior: "smooth",
        });
      }
    });
  });

  /* ----- IntersectionObserver Fade-In Animations ----- */
  var fadeElements = document.querySelectorAll(".fade-in");

  if ("IntersectionObserver" in window && fadeElements.length > 0) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.12,
        rootMargin: "0px 0px -40px 0px",
      }
    );

    fadeElements.forEach(function (el) {
      observer.observe(el);
    });
  } else {
    // Fallback: show all elements immediately
    fadeElements.forEach(function (el) {
      el.classList.add("visible");
    });
  }

  /* ----- Contact Form Handling ----- */
  var contactForm = document.getElementById("contactForm");

  if (contactForm) {
    contactForm.addEventListener("submit", function (e) {
      e.preventDefault();

      // Basic validation
      var name = contactForm.querySelector('[name="name"]');
      var email = contactForm.querySelector('[name="email"]');
      var message = contactForm.querySelector('[name="message"]');
      var errors = [];

      if (!name || name.value.trim() === "") {
        errors.push("Please enter your name.");
      }

      if (!email || !isValidEmail(email.value)) {
        errors.push("Please enter a valid email address.");
      }

      if (!message || message.value.trim().length < 10) {
        errors.push("Please enter a message (at least 10 characters).");
      }

      if (errors.length > 0) {
        showFormMessage(errors.join(" "), "error");
        return;
      }

      // Simulate submission
      var submitBtn = contactForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Sending...";
      }

      setTimeout(function () {
        showFormMessage(
          "Thank you for your inquiry. One of our advisors will contact you within one business day.",
          "success"
        );
        contactForm.reset();
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = "Send Message";
        }
      }, 1200);
    });
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function showFormMessage(text, type) {
    var existing = document.querySelector(".form-message");
    if (existing) existing.remove();

    var msg = document.createElement("div");
    msg.className = "form-message";
    msg.textContent = text;
    msg.style.padding = "1rem 1.25rem";
    msg.style.marginTop = "1rem";
    msg.style.borderRadius = "3px";
    msg.style.fontSize = "0.95rem";
    msg.style.fontWeight = "500";

    if (type === "success") {
      msg.style.background = "#e8f5e9";
      msg.style.color = "#0d4f3c";
      msg.style.border = "1px solid #a5d6a7";
    } else {
      msg.style.background = "#fce4ec";
      msg.style.color = "#c62828";
      msg.style.border = "1px solid #ef9a9a";
    }

    contactForm.appendChild(msg);

    setTimeout(function () {
      if (msg.parentNode) msg.remove();
    }, 8000);
  }

  /* ----- Active Nav Link Highlighting ----- */
  var currentPage = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-links a").forEach(function (link) {
    var href = link.getAttribute("href");
    if (href === currentPage) {
      link.classList.add("active");
    }
  });

  /* ----- Close mobile nav on outside click ----- */
  document.addEventListener("click", function (e) {
    if (
      navLinks &&
      navLinks.classList.contains("open") &&
      !navLinks.contains(e.target) &&
      !hamburger.contains(e.target)
    ) {
      hamburger.classList.remove("active");
      navLinks.classList.remove("open");
    }
  });
})();
