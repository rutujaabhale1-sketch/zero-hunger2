// Zero Hunger Website - Secure JavaScript Implementation
// Security-focused form validation and interactions

// Security configuration
const SECURITY_CONFIG = {
    maxFormSubmissions: 5,
    submissionTimeout: 60000, // 1 minute
    maxInputLength: 500,
    allowedEmailDomains: ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'],
    rateLimitWindow: 300000, // 5 minutes
    csrfToken: generateCSRFToken()
};

// Rate limiting storage
const rateLimitStore = new Map();

// Generate CSRF token
function generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Security utility functions
const SecurityUtils = {
    // Sanitize input to prevent XSS
    sanitizeInput: (input) => {
        if (typeof input !== 'string') return '';
        return input
            .replace(/[<>]/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .trim()
            .substring(0, SECURITY_CONFIG.maxInputLength);
    },

    // Validate email format
    validateEmail: (email) => {
        const sanitized = SecurityUtils.sanitizeInput(email);
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(sanitized);
    },

    // Validate phone number
    validatePhone: (phone) => {
        const sanitized = SecurityUtils.sanitizeInput(phone);
        const phoneRegex = /^[\d\s\-\+\(\)]+$/;
        return phoneRegex.test(sanitized) && sanitized.replace(/\D/g, '').length >= 10;
    },

    // Validate name (letters only)
    validateName: (name) => {
        const sanitized = SecurityUtils.sanitizeInput(name);
        const nameRegex = /^[a-zA-Z\s\-']+$/;
        return nameRegex.test(sanitized) && sanitized.length >= 2 && sanitized.length <= 50;
    },

    // Rate limiting check
    checkRateLimit: (identifier) => {
        const now = Date.now();
        const submissions = rateLimitStore.get(identifier) || [];
        
        // Remove old submissions outside the window
        const recentSubmissions = submissions.filter(time => 
            now - time < SECURITY_CONFIG.rateLimitWindow
        );
        
        if (recentSubmissions.length >= SECURITY_CONFIG.maxFormSubmissions) {
            return false;
        }
        
        recentSubmissions.push(now);
        rateLimitStore.set(identifier, recentSubmissions);
        return true;
    },

    // Detect suspicious patterns
    detectSuspiciousActivity: (formData) => {
        const suspiciousPatterns = [
            /script|javascript|onload|onerror/gi,
            /<iframe|<object|<embed/gi,
            /eval\(|exec\(|system\(/gi,
            /\$\{.*\}/gi,
            /union.*select|drop.*table|insert.*into/gi
        ];

        const dataString = JSON.stringify(formData).toLowerCase();
        return suspiciousPatterns.some(pattern => pattern.test(dataString));
    }
};

// Form validation and submission handler
class SecureFormHandler {
    constructor(formId, formType) {
        this.form = document.getElementById(formId);
        this.formType = formType;
        this.setupEventListeners();
    }

    setupEventListeners() {
        if (!this.form) return;

        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSecureSubmission();
        });

        // Add real-time validation
        const inputs = this.form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('blur', () => this.validateField(input));
            input.addEventListener('input', () => this.clearFieldError(input));
        });
    }

    validateField(field) {
        const value = SecurityUtils.sanitizeInput(field.value);
        const fieldName = field.name || field.id;
        let isValid = true;
        let errorMessage = '';

        // Required field validation
        if (field.hasAttribute('required') && !value) {
            isValid = false;
            errorMessage = 'This field is required';
        }

        // Specific field validations
        switch (field.type) {
            case 'email':
                if (value && !SecurityUtils.validateEmail(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid email address';
                }
                break;
            case 'tel':
                if (value && !SecurityUtils.validatePhone(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid phone number';
                }
                break;
            case 'text':
                if (fieldName.includes('name') && value && !SecurityUtils.validateName(value)) {
                    isValid = false;
                    errorMessage = 'Name should only contain letters';
                }
                break;
        }

        this.showFieldError(field, isValid, errorMessage);
        return isValid;
    }

    showFieldError(field, isValid, message) {
        const errorElement = field.parentNode.querySelector('.error-message') || 
                           this.createErrorElement(field);
        
        if (!isValid) {
            field.classList.add('border-red-500');
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        } else {
            field.classList.remove('border-red-500');
            errorElement.style.display = 'none';
        }
    }

    clearFieldError(field) {
        field.classList.remove('border-red-500');
        const errorElement = field.parentNode.querySelector('.error-message');
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    createErrorElement(field) {
        const errorElement = document.createElement('div');
        errorElement.className = 'error-message text-red-500 text-sm mt-1';
        errorElement.style.display = 'none';
        field.parentNode.appendChild(errorElement);
        return errorElement;
    }

    async handleSecureSubmission() {
        // Validate all fields
        const inputs = this.form.querySelectorAll('input[required], textarea[required], select[required]');
        let isFormValid = true;

        inputs.forEach(input => {
            if (!this.validateField(input)) {
                isFormValid = false;
            }
        });

        if (!isFormValid) {
            this.showMessage('Please correct the errors in the form', 'error');
            return;
        }

        // Collect and sanitize form data
        const formData = this.collectFormData();
        
        // Security checks
        if (!this.performSecurityChecks(formData)) {
            return;
        }

        // Show loading state
        this.setLoadingState(true);

        try {
            // Simulate secure API call
            await this.submitSecurely(formData);
            this.showMessage(`${this.formType} submitted successfully! We'll contact you soon.`, 'success');
            this.form.reset();
        } catch (error) {
            this.showMessage('An error occurred. Please try again later.', 'error');
            console.error('Submission error:', error);
        } finally {
            this.setLoadingState(false);
        }
    }

    collectFormData() {
        const formData = {};
        const inputs = this.form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
            const name = input.name || input.id;
            if (name) {
                formData[name] = SecurityUtils.sanitizeInput(input.value);
            }
        });

        return formData;
    }

    performSecurityChecks(formData) {
        // Check rate limiting
        const identifier = formData.email || formData.phone || 'anonymous';
        if (!SecurityUtils.checkRateLimit(identifier)) {
            this.showMessage('Too many submissions. Please try again later.', 'error');
            return false;
        }

        // Detect suspicious activity
        if (SecurityUtils.detectSuspiciousActivity(formData)) {
            this.showMessage('Invalid submission detected.', 'error');
            console.warn('Suspicious activity detected:', formData);
            return false;
        }

        return true;
    }

    async submitSecurely(formData) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 2000));

        // In a real application, this would be a secure API call
        const response = await fetch('/api/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': SECURITY_CONFIG.csrfToken
            },
            body: JSON.stringify({
                ...formData,
                formType: this.formType,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent.substring(0, 200)
            })
        });

        if (!response.ok) {
            throw new Error('Submission failed');
        }

        return response.json();
    }

    setLoadingState(loading) {
        const submitButton = this.form.querySelector('button[type="submit"]');
        if (loading) {
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner"></span> Processing...';
        } else {
            submitButton.disabled = false;
            submitButton.innerHTML = submitButton.getAttribute('data-original-text') || 'Submit';
        }
    }

    showMessage(message, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${
            type === 'success' ? 'bg-green-500 text-white' : 'bg-red-500 text-white'
        }`;
        messageDiv.textContent = message;
        document.body.appendChild(messageDiv);

        setTimeout(() => {
            messageDiv.remove();
        }, 5000);
    }
}

// Initialize secure form handlers
document.addEventListener('DOMContentLoaded', () => {
    // Initialize all forms with security
    new SecureFormHandler('donation-form', 'Donation');
    new SecureFormHandler('request-form', 'Food Request');
    new SecureFormHandler('volunteer-form', 'Volunteer Registration');

    // Initialize other features
    initializeMobileMenu();
    initializeStats();
    initializeFoodBankSearch();
    initializeSmoothScrolling();
    initializeInteractiveMap();
});

// Mobile menu functionality
function initializeMobileMenu() {
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');

    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', () => {
            mobileMenu.classList.toggle('show');
        });

        // Close menu when clicking on links
        const menuLinks = mobileMenu.querySelectorAll('a');
        menuLinks.forEach(link => {
            link.addEventListener('click', () => {
                mobileMenu.classList.remove('show');
            });
        });
    }
}

// Animated statistics counter
function initializeStats() {
    const statElements = document.querySelectorAll('.stat-item [data-target]');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const element = entry.target;
                const target = parseInt(element.getAttribute('data-target'));
                animateCounter(element, target);
                observer.unobserve(element);
            }
        });
    });

    statElements.forEach(element => {
        observer.observe(element);
    });
}

function animateCounter(element, target) {
    let current = 0;
    const increment = target / 100;
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current).toLocaleString();
    }, 20);
}

// Food bank search functionality
function initializeFoodBankSearch() {
    const searchInput = document.getElementById('location-search');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchFoodBanks();
            }
        });
    }
}

function searchFoodBanks() {
    const searchInput = document.getElementById('location-search');
    const resultsContainer = document.getElementById('food-banks-results');
    
    if (!searchInput || !resultsContainer) return;

    const location = SecurityUtils.sanitizeInput(searchInput.value);
    if (!location) {
        showMessage('Please enter a location', 'error');
        return;
    }

    // Show loading state
    resultsContainer.innerHTML = '<div class="col-span-full text-center"><div class="spinner mx-auto"></div><p class="mt-4">Searching food banks...</p></div>';

    // Simulate API call
    setTimeout(() => {
        displayFoodBanks(location);
    }, 1500);
}

function displayFoodBanks(location) {
    const resultsContainer = document.getElementById('food-banks-results');
    
    // Mock food bank data
    const foodBanks = [
        {
            name: 'Community Food Center',
            address: '123 Main St, ' + location,
            phone: '(555) 123-4567',
            hours: 'Mon-Fri: 9AM-6PM',
            distance: '0.5 miles',
            status: 'open'
        },
        {
            name: 'Hope Kitchen',
            address: '456 Oak Ave, ' + location,
            phone: '(555) 987-6543',
            hours: 'Daily: 11AM-7PM',
            distance: '1.2 miles',
            status: 'open'
        },
        {
            name: 'Neighborhood Pantry',
            address: '789 Elm St, ' + location,
            phone: '(555) 456-7890',
            hours: 'Tue-Sat: 10AM-4PM',
            distance: '2.0 miles',
            status: 'limited'
        }
    ];

    let html = '';
    foodBanks.forEach(bank => {
        html += `
            <div class="food-bank-card">
                <h3 class="text-lg font-semibold mb-2">${bank.name}</h3>
                <p class="text-gray-600 mb-2"><i class="fas fa-map-marker-alt mr-2"></i>${bank.address}</p>
                <p class="text-gray-600 mb-2"><i class="fas fa-phone mr-2"></i>${bank.phone}</p>
                <p class="text-gray-600 mb-2"><i class="fas fa-clock mr-2"></i>${bank.hours}</p>
                <div class="flex justify-between items-center mt-4">
                    <span class="distance">${bank.distance}</span>
                    <span class="status ${bank.status}">${bank.status === 'open' ? 'Open' : 'Limited Supply'}</span>
                </div>
                <button class="w-full mt-4 bg-green-600 text-white py-2 rounded hover:bg-green-700 transition">
                    Get Directions
                </button>
            </div>
        `;
    });

    resultsContainer.innerHTML = html || '<p class="col-span-full text-center text-gray-600">No food banks found near ' + location + '</p>';
}

// Smooth scrolling
function initializeSmoothScrolling() {
    const links = document.querySelectorAll('a[href^="#"]');
    links.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
}

// Utility function for scrolling to sections
function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// Global message function
function showMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${
        type === 'success' ? 'bg-green-500 text-white' : 'bg-red-500 text-white'
    }`;
    messageDiv.textContent = message;
    document.body.appendChild(messageDiv);

    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}

// Security headers and CSP (would be implemented server-side)
const SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

// Log security events (in production, this would go to a security monitoring service)
function logSecurityEvent(event, data) {
    const securityLog = {
        timestamp: new Date().toISOString(),
        event,
        data,
        userAgent: navigator.userAgent,
        ip: 'client-ip' // Would be filled server-side
    };
    
    console.warn('Security Event:', securityLog);
    // In production, send to security monitoring service
}

// Interactive Map Implementation
let map;
let markers = [];
let userLocationMarker;
let circle;

// Sample location data (in production, this would come from a database)
const locationData = [
    {
        id: 1,
        name: 'Central Food Bank',
        type: 'food-bank',
        lat: 40.7128,
        lng: -74.0060,
        address: '123 Main St, New York, NY',
        phone: '(555) 123-4567',
        hours: 'Mon-Fri: 9AM-6PM',
        description: 'Main food distribution center'
    },
    {
        id: 2,
        name: 'Community Donation Center',
        type: 'donation-center',
        lat: 40.7580,
        lng: -73.9855,
        address: '456 Oak Ave, New York, NY',
        phone: '(555) 987-6543',
        hours: 'Daily: 8AM-8PM',
        description: 'Food donation drop-off point'
    },
    {
        id: 3,
        name: 'Emergency Request Point',
        type: 'request-point',
        lat: 40.7489,
        lng: -73.9680,
        address: '789 Elm St, New York, NY',
        phone: '(555) 456-7890',
        hours: '24/7 Emergency',
        description: 'Emergency food assistance'
    },
    {
        id: 4,
        name: 'Volunteer Hub',
        type: 'volunteer-hub',
        lat: 40.7282,
        lng: -73.9942,
        address: '321 Pine St, New York, NY',
        phone: '(555) 234-5678',
        hours: 'Mon-Sat: 10AM-6PM',
        description: 'Volunteer coordination center'
    },
    {
        id: 5,
        name: 'West Side Food Pantry',
        type: 'food-bank',
        lat: 40.7831,
        lng: -73.9712,
        address: '567 Maple Dr, New York, NY',
        phone: '(555) 345-6789',
        hours: 'Tue-Sun: 11AM-5PM',
        description: 'Local food pantry'
    }
];

function initializeInteractiveMap() {
    // Initialize the map centered on New York
    map = L.map('interactive-map').setView([40.7128, -74.0060], 12);

    // Add OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
    }).addTo(map);

    // Add all location markers
    addLocationMarkers();

    // Add search functionality
    const searchInput = document.getElementById('map-search');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchMapLocation();
            }
        });
    }
}

function addLocationMarkers(filter = 'all') {
    // Clear existing markers
    markers.forEach(marker => map.removeLayer(marker));
    markers = [];

    // Filter locations based on selected type
    const filteredLocations = filter === 'all' 
        ? locationData 
        : locationData.filter(loc => loc.type === filter);

    // Add markers for filtered locations
    filteredLocations.forEach(location => {
        const color = getLocationColor(location.type);
        const icon = L.divIcon({
            className: 'custom-marker',
            html: `<div style="background-color: ${color}; width: 30px; height: 30px; border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 6px rgba(0,0,0,0.3);"></div>`,
            iconSize: [30, 30],
            iconAnchor: [15, 15]
        });

        const marker = L.marker([location.lat, location.lng], { icon })
            .addTo(map)
            .bindPopup(createPopupContent(location));

        markers.push(marker);
    });
}

function getLocationColor(type) {
    const colors = {
        'food-bank': '#16a34a',
        'donation-center': '#2563eb',
        'request-point': '#ea580c',
        'volunteer-hub': '#9333ea'
    };
    return colors[type] || '#6b7280';
}

function createPopupContent(location) {
    return `
        <div style="min-width: 200px;">
            <h3 style="margin: 0 0 10px 0; color: #1f2937; font-weight: bold;">${location.name}</h3>
            <p style="margin: 5px 0; color: #6b7280; font-size: 14px;"><i class="fas fa-map-marker-alt"></i> ${location.address}</p>
            <p style="margin: 5px 0; color: #6b7280; font-size: 14px;"><i class="fas fa-phone"></i> ${location.phone}</p>
            <p style="margin: 5px 0; color: #6b7280; font-size: 14px;"><i class="fas fa-clock"></i> ${location.hours}</p>
            <p style="margin: 5px 0; color: #6b7280; font-size: 12px;">${location.description}</p>
            <button onclick="getDirections(${location.lat}, ${location.lng})" style="margin-top: 10px; background: #16a34a; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 14px;">
                <i class="fas fa-directions"></i> Get Directions
            </button>
        </div>
    `;
}

function getCurrentLocation() {
    if (navigator.geolocation) {
        const button = event.target;
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Getting location...';

        navigator.geolocation.getCurrentPosition(
            (position) => {
                const lat = position.coords.latitude;
                const lng = position.coords.longitude;

                // Remove previous user location marker
                if (userLocationMarker) {
                    map.removeLayer(userLocationMarker);
                }
                if (circle) {
                    map.removeLayer(circle);
                }

                // Add user location marker
                userLocationMarker = L.marker([lat, lng], {
                    icon: L.divIcon({
                        className: 'user-location-marker',
                        html: '<div style="background-color: #3b82f6; width: 20px; height: 20px; border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 6px rgba(0,0,0,0.3);"></div>',
                        iconSize: [20, 20],
                        iconAnchor: [10, 10]
                    })
                }).addTo(map);

                // Add accuracy circle
                circle = L.circle([lat, lng], {
                    color: '#3b82f6',
                    fillColor: '#3b82f6',
                    fillOpacity: 0.1,
                    radius: position.coords.accuracy
                }).addTo(map);

                // Center map on user location
                map.setView([lat, lng], 13);

                // Show nearby locations
                showNearbyLocations(lat, lng);

                button.disabled = false;
                button.innerHTML = '<i class="fas fa-location-crosshairs mr-2"></i>Use My Location';
                
                showMessage('Location found! Showing nearby food assistance locations.', 'success');
            },
            (error) => {
                button.disabled = false;
                button.innerHTML = '<i class="fas fa-location-crosshairs mr-2"></i>Use My Location';
                
                let errorMessage = 'Unable to get your location.';
                switch(error.code) {
                    case error.PERMISSION_DENIED:
                        errorMessage = 'Location access denied. Please enable location services.';
                        break;
                    case error.POSITION_UNAVAILABLE:
                        errorMessage = 'Location information unavailable.';
                        break;
                    case error.TIMEOUT:
                        errorMessage = 'Location request timed out.';
                        break;
                }
                showMessage(errorMessage, 'error');
            }
        );
    } else {
        showMessage('Geolocation is not supported by your browser.', 'error');
    }
}

function showNearbyLocations(userLat, userLng) {
    const nearbyLocations = locationData.filter(location => {
        const distance = calculateDistance(userLat, userLng, location.lat, location.lng);
        return distance <= 5; // Within 5 miles
    });

    if (nearbyLocations.length > 0) {
        let nearbyInfo = 'Nearby locations:\n';
        nearbyLocations.forEach(location => {
            const distance = calculateDistance(userLat, userLng, location.lat, location.lng);
            nearbyInfo += `${location.name} (${distance.toFixed(1)} miles)\n`;
        });
        showMessage(nearbyInfo, 'success');
    } else {
        showMessage('No food assistance locations found within 5 miles of your location.', 'error');
    }
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 3959; // Earth's radius in miles
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function searchMapLocation() {
    const searchInput = document.getElementById('map-search');
    const query = SecurityUtils.sanitizeInput(searchInput.value);
    
    if (!query) {
        showMessage('Please enter a location to search', 'error');
        return;
    }

    // In a real application, this would use a geocoding API
    // For demo purposes, we'll simulate a search
    showMessage(`Searching for locations near "${query}"...`, 'info');

    // Simulate API call
    setTimeout(() => {
        // For demo, center on a random location
        const randomLocation = locationData[Math.floor(Math.random() * locationData.length)];
        map.setView([randomLocation.lat, randomLocation.lng], 14);
        
        // Open the popup for the found location
        const marker = markers.find(m => 
            m.getLatLng().lat === randomLocation.lat && 
            m.getLatLng().lng === randomLocation.lng
        );
        if (marker) {
            marker.openPopup();
        }
        
        showMessage(`Found locations near "${query}"`, 'success');
    }, 1500);
}

function filterMapLocations() {
    const filter = document.getElementById('location-filter').value;
    addLocationMarkers(filter);
    
    const filterText = filter === 'all' ? 'all locations' : filter.replace('-', ' ');
    showMessage(`Showing ${filterText}`, 'info');
}

function getDirections(lat, lng) {
    // Open Google Maps with directions
    const url = `https://www.google.com/maps/dir/?api=1&destination=${lat},${lng}`;
    window.open(url, '_blank');
    
    // Log the directions request (for analytics)
    logSecurityEvent('directions_requested', { lat, lng });
}
