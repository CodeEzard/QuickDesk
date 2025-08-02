package main

import (
	"log"
	"net/http"
	"os"
	"quickdesk-backend/internal/config"
	"quickdesk-backend/internal/controllers"
	"quickdesk-backend/internal/middleware"
	"quickdesk-backend/internal/models"
	"quickdesk-backend/pkg/database"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
    createTestUsers(db)
	// Initialize Chi router
	r := chi.NewRouter()

	// Configure middleware
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)

	// Configure CORS
	// Configure CORS
// Configure CORS
r.Use(cors.Handler(cors.Options{
    AllowedOrigins: []string{
        "http://localhost:8081",
        "http://localhost:5173", 
        "http://localhost:3000",
        "http://192.168.29.117:8081",  // Add this line for your network IP
        "http://127.0.0.1:8081",       // Add this for localhost alias
    },
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
    ExposedHeaders:   []string{"Link"},
    AllowCredentials: true,
    MaxAge:           300,
}))

	// Initialize controllers
	authController := controllers.NewAuthController(db)
	userController := controllers.NewUserController(db)
	ticketController := controllers.NewTicketController(db)
	categoryController := controllers.NewCategoryController(db)

	// API routes
	r.Route("/api", func(r chi.Router) {
		// Authentication routes (public)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authController.Register)
			r.Post("/login", authController.Login)
			r.Post("/logout", authController.Logout)
		})

// Protected routes
r.Group(func(r chi.Router) {
	r.Use(middleware.AuthMiddleware(db)) // Add (db) parameter

	// User routes
	r.Route("/users", func(r chi.Router) {
		r.Get("/", userController.GetUsers)
		r.Get("/{id}", userController.GetUser)
		r.Put("/{id}", userController.UpdateUser)
		r.Delete("/{id}", userController.DeleteUser)
	})

			// Ticket routes
			// ...existing code...

// Ticket routes
			r.Route("/tickets", func(r chi.Router) {
				r.Get("/", ticketController.GetTickets)              // List all tickets
				r.Post("/", ticketController.CreateTicket)           // Create a new ticket
				r.Route("/{id}", func(r chi.Router) {
        			r.Get("/", ticketController.GetTicket)           // Get a specific ticket
        			r.Put("/", ticketController.UpdateTicket)        // Update a specific ticket
        			r.Delete("/", ticketController.DeleteTicket)     // Delete a specific ticket
        			r.Post("/comments", ticketController.AddComment) // Add comment to a ticket
        			r.Post("/vote", ticketController.VoteTicket)     // Vote on a ticket
        			r.Post("/assign", ticketController.AssignTicket) // Assign a ticket
    			})
			})

// ...existing code...

			// Category routes (admin only)
			r.Route("/categories", func(r chi.Router) {
				r.Get("/", categoryController.GetCategories)

				// Admin only routes
				r.Group(func(r chi.Router) {
					r.Use(middleware.AdminMiddleware)
					r.Post("/", categoryController.CreateCategory)
					r.Put("/{id}", categoryController.UpdateCategory)
					r.Delete("/{id}", categoryController.DeleteCategory)
				})
			})
		})
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Add this function to create test users
func createTestUsers(db *gorm.DB) {
    testUsers := []struct {
        Email    string
        Password string
        Name     string
        Role     string
    }{
        {
            Email:    "admin@quickdesk.com",
            Password: "password",
            Name:     "Admin User",
            Role:     "admin",
        },
        {
            Email:    "agent@quickdesk.com",
            Password: "password",
            Name:     "Agent User",
            Role:     "agent",
        },
        {
            Email:    "user@quickdesk.com",
            Password: "password",
            Name:     "Regular User",
            Role:     "user",
        },
    }

    for _, userData := range testUsers {
        var existingUser models.User
        result := db.Where("email = ?", userData.Email).First(&existingUser)
        
        if result.Error != nil {
            // User doesn't exist, create one
            hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
            if err != nil {
                log.Printf("Error hashing password for %s: %v", userData.Email, err)
                continue
            }
            
			newUser := models.User{
				ID:        uuid.New(),
				Email:     userData.Email,
				FirstName: userData.Name, // Using Name as FirstName for now
				LastName:  "",            // Empty LastName as placeholder
				Password:  string(hashedPassword),
				Role:     models.Role(userData.Role),
			}
            
            if err := db.Create(&newUser).Error; err != nil {
                log.Printf("Error creating user %s: %v", userData.Email, err)
                continue
            }
            
            log.Printf("✅ Test user created: %s (%s) / password", userData.Email, userData.Role)
        } else {
            log.Printf("✅ Test user already exists: %s (%s)", userData.Email, userData.Role)
        }
    }
    
    log.Println("\n🚀 Demo Accounts:")
    log.Println("Admin: admin@quickdesk.com / password")
    log.Println("Agent: agent@quickdesk.com / password")
    log.Println("User: user@quickdesk.com / password")
}