/* ========================================
   {{COMPANY_NAME}} — Main JavaScript
   No external dependencies
   ======================================== */

(function () {
    'use strict';

    // ========== Mobile Navigation ==========
    const navToggle = document.querySelector('.nav-toggle');
    const mainNav = document.querySelector('.main-nav');

    if (navToggle && mainNav) {
        navToggle.addEventListener('click', function () {
            navToggle.classList.toggle('active');
            mainNav.classList.toggle('open');
            document.body.style.overflow = mainNav.classList.contains('open') ? 'hidden' : '';
        });

        // Close nav when clicking a link
        mainNav.querySelectorAll('a').forEach(function (link) {
            link.addEventListener('click', function () {
                navToggle.classList.remove('active');
                mainNav.classList.remove('open');
                document.body.style.overflow = '';
            });
        });

        // Close nav on outside click
        document.addEventListener('click', function (e) {
            if (mainNav.classList.contains('open') &&
                !mainNav.contains(e.target) &&
                !navToggle.contains(e.target)) {
                navToggle.classList.remove('active');
                mainNav.classList.remove('open');
                document.body.style.overflow = '';
            }
        });
    }

    // ========== Smooth Scrolling ==========
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
        anchor.addEventListener('click', function (e) {
            var targetId = this.getAttribute('href');
            if (targetId === '#') return;

            var target = document.querySelector(targetId);
            if (target) {
                e.preventDefault();
                var headerHeight = document.querySelector('.site-header')
                    ? document.querySelector('.site-header').offsetHeight
                    : 0;
                var targetPosition = target.getBoundingClientRect().top + window.pageYOffset - headerHeight - 20;

                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // ========== Intersection Observer — Fade In ==========
    if ('IntersectionObserver' in window) {
        var fadeElements = document.querySelectorAll('.fade-in');
        var fadeObserver = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    fadeObserver.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -40px 0px'
        });

        fadeElements.forEach(function (el) {
            fadeObserver.observe(el);
        });
    } else {
        // Fallback: show all elements
        document.querySelectorAll('.fade-in').forEach(function (el) {
            el.classList.add('visible');
        });
    }

    // ========== Active Nav Link ==========
    var currentPage = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.main-nav a').forEach(function (link) {
        var href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'index.html')) {
            link.classList.add('active');
        }
    });

    // ========== Form Handling ==========
    function handleFormSubmit(form, successMessage) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();

            // Basic validation
            var requiredFields = form.querySelectorAll('[required]');
            var valid = true;

            requiredFields.forEach(function (field) {
                if (!field.value.trim()) {
                    valid = false;
                    field.style.borderColor = '#ef4444';
                } else {
                    field.style.borderColor = '';
                }
            });

            // Email validation
            var emailField = form.querySelector('input[type="email"]');
            if (emailField && emailField.value) {
                var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailPattern.test(emailField.value)) {
                    valid = false;
                    emailField.style.borderColor = '#ef4444';
                }
            }

            if (!valid) return;

            // Show success message
            var existingMessage = form.querySelector('.form-message');
            if (existingMessage) {
                existingMessage.remove();
            }

            var messageDiv = document.createElement('div');
            messageDiv.className = 'form-message success';
            messageDiv.textContent = successMessage;
            form.insertBefore(messageDiv, form.firstChild);

            form.reset();

            // Remove message after 5 seconds
            setTimeout(function () {
                messageDiv.style.opacity = '0';
                messageDiv.style.transition = 'opacity 0.3s ease';
                setTimeout(function () {
                    messageDiv.remove();
                }, 300);
            }, 5000);
        });
    }

    // Contact form
    var contactForm = document.getElementById('contact-form');
    if (contactForm) {
        handleFormSubmit(contactForm, 'Thank you for your inquiry! Our reservations team will respond within 24 hours.');
    }

    // Newsletter form
    var newsletterForm = document.getElementById('newsletter-form');
    if (newsletterForm) {
        handleFormSubmit(newsletterForm, 'Welcome! You\'ll receive exclusive travel offers and destination guides.');
    }

    // ========== Header Scroll Effect ==========
    var header = document.querySelector('.site-header');
    if (header) {
        var lastScroll = 0;
        window.addEventListener('scroll', function () {
            var currentScroll = window.pageYOffset;
            if (currentScroll > 80) {
                header.style.boxShadow = '0 2px 12px rgba(26, 26, 46, 0.08)';
            } else {
                header.style.boxShadow = '';
            }
            lastScroll = currentScroll;
        }, { passive: true });
    }

    // ========== Year in Footer ==========
    var yearEl = document.getElementById('current-year');
    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }

})();
