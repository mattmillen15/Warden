/**
 * {{COMPANY_NAME}} — Main JavaScript
 * No external dependencies
 */

(function () {
  "use strict";

  // ---- Mobile Navigation ----
  const navToggle = document.querySelector(".nav-toggle");
  const navLinks = document.querySelector(".nav-links");

  if (navToggle && navLinks) {
    navToggle.addEventListener("click", function () {
      navToggle.classList.toggle("active");
      navLinks.classList.toggle("active");
    });

    // Close menu on link click
    navLinks.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        navToggle.classList.remove("active");
        navLinks.classList.remove("active");
      });
    });

    // Close menu on outside click
    document.addEventListener("click", function (e) {
      if (!navToggle.contains(e.target) && !navLinks.contains(e.target)) {
        navToggle.classList.remove("active");
        navLinks.classList.remove("active");
      }
    });
  }

  // ---- Sticky Header Shadow ----
  const header = document.querySelector(".header");
  if (header) {
    window.addEventListener("scroll", function () {
      if (window.scrollY > 10) {
        header.classList.add("scrolled");
      } else {
        header.classList.remove("scrolled");
      }
    });
  }

  // ---- Smooth Scroll for Anchor Links ----
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener("click", function (e) {
      var targetId = this.getAttribute("href");
      if (targetId === "#") return;
      var target = document.querySelector(targetId);
      if (target) {
        e.preventDefault();
        var headerHeight = header ? header.offsetHeight : 0;
        var targetPosition =
          target.getBoundingClientRect().top + window.pageYOffset - headerHeight - 20;
        window.scrollTo({
          top: targetPosition,
          behavior: "smooth",
        });
      }
    });
  });

  // ---- IntersectionObserver Fade-In ----
  var fadeElements = document.querySelectorAll(".fade-in");
  if (fadeElements.length > 0 && "IntersectionObserver" in window) {
    var fadeObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            fadeObserver.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.12,
        rootMargin: "0px 0px -40px 0px",
      }
    );

    fadeElements.forEach(function (el) {
      fadeObserver.observe(el);
    });
  } else {
    // Fallback: show all immediately
    fadeElements.forEach(function (el) {
      el.classList.add("visible");
    });
  }

  // ---- Contact Form Handling ----
  var contactForm = document.getElementById("contactForm");
  var formSuccess = document.querySelector(".form-success");

  if (contactForm) {
    contactForm.addEventListener("submit", function (e) {
      e.preventDefault();

      // Basic validation
      var isValid = true;
      var requiredFields = contactForm.querySelectorAll("[required]");
      requiredFields.forEach(function (field) {
        if (!field.value.trim()) {
          isValid = false;
          field.style.borderColor = "#ef4444";
        } else {
          field.style.borderColor = "";
        }
      });

      // Email validation
      var emailField = contactForm.querySelector('input[type="email"]');
      if (emailField && emailField.value) {
        var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(emailField.value)) {
          isValid = false;
          emailField.style.borderColor = "#ef4444";
        }
      }

      // Phone validation
      var phoneField = contactForm.querySelector('input[type="tel"]');
      if (phoneField && phoneField.value) {
        var phoneClean = phoneField.value.replace(/[\s\-\(\)\.]/g, "");
        if (phoneClean.length < 10) {
          isValid = false;
          phoneField.style.borderColor = "#ef4444";
        }
      }

      if (!isValid) return;

      // Simulate form submission
      var submitBtn = contactForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Sending...";
      }

      setTimeout(function () {
        contactForm.style.display = "none";
        if (formSuccess) {
          formSuccess.classList.add("show");
        }
      }, 1200);
    });

    // Remove error styling on input
    contactForm.querySelectorAll("input, select, textarea").forEach(function (field) {
      field.addEventListener("input", function () {
        this.style.borderColor = "";
      });
    });
  }

  // ---- Active Nav Link Highlight ----
  var currentPage = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-links a").forEach(function (link) {
    var href = link.getAttribute("href");
    if (href === currentPage || (currentPage === "" && href === "index.html")) {
      link.classList.add("active");
    }
  });

  // ---- Phone Number Click Tracking (placeholder) ----
  document.querySelectorAll('a[href^="tel:"]').forEach(function (link) {
    link.addEventListener("click", function () {
      if (typeof gtag === "function") {
        gtag("event", "click", {
          event_category: "Contact",
          event_label: "Phone Call",
        });
      }
    });
  });
})();
