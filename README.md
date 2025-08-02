# QuickDesk Backend

## Setup Instructions

### Prerequisites
- Go 1.21 or higher
- PostgreSQL 13 or higher

### Installation

1. Clone the repository
2. Copy environment variables:
   ```bash
   cp .env.example .env
   ```

3. Update the `.env` file with your configuration:
   - Database connection string
   - JWT secret key
   - Email configuration (optional)

4. Install dependencies:
   ```bash
   go mod tidy
   ```

5. Run the application:
   ```bash
   go run main.go
   ```

The server will start on `http://localhost:8080` (or the port specified in your .env file).

## Database Setup

### PostgreSQL Setup
1. Create a new database:
   ```sql
   CREATE DATABASE quickdesk_db;
   ```

2. Update the `DATABASE_URL` in your `.env` file with your PostgreSQL credentials.

3. The application will automatically run migrations on startup.

## API Documentation

### Authentication Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### Ticket Endpoints
- `GET /api/tickets` - Get tickets with filters
- `POST /api/tickets` - Create new ticket
- `GET /api/tickets/:id` - Get ticket details
- `PUT /api/tickets/:id` - Update ticket
- `DELETE /api/tickets/:id` - Delete ticket
- `POST /api/tickets/:id/comments` - Add comment
- `POST /api/tickets/:id/vote` - Vote on ticket
- `POST /api/tickets/:id/assign` - Assign ticket

### User Endpoints
- `GET /api/users` - Get users (admin only)
- `GET /api/users/:id` - Get user details
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (admin only)

### Category Endpoints
- `GET /api/categories` - Get all categories
- `POST /api/categories` - Create category (admin only)
- `PUT /api/categories/:id` - Update category (admin only)
- `DELETE /api/categories/:id` - Delete category (admin only)

## Project Structure

```
├── cmd/
│   └── server/          # Application entry point
├── internal/
│   ├── controllers/     # HTTP handlers
│   ├── models/         # GORM models
│   ├── middleware/     # Custom middleware
│   └── config/         # Configuration management
├── pkg/
│   ├── auth/           # Authentication utilities
│   ├── email/          # Email service
│   └── database/       # Database connection
├── uploads/            # File uploads directory
├── .env.example        # Environment variables template
├── go.mod             # Go module file
├── go.sum             # Go dependencies
└── main.go            # Application entry point
```

## Features

### User Management
- User registration and authentication
- Role-based access control (User, Agent, Admin)
- JWT-based authentication

### Ticket Management
- Create, read, update, delete tickets
- Ticket assignment to agents
- Status tracking (Open → In Progress → Resolved → Closed)
- Priority levels (Low, Medium, High, Urgent)
- Category classification

### Comments and Communication
- Threaded comments on tickets
- Internal comments for agents
- Real-time updates

### Voting System
- Upvote/downvote tickets
- Vote tracking and statistics

### Search and Filtering
- Search tickets by subject/description
- Filter by status, category, assignee
- Sort by creation date, most replied, etc.
- Pagination support

### Email Notifications
- Ticket creation notifications
- Status update notifications
- Assignment notifications
- Comment notifications

## Security Features
- Password hashing with bcrypt
- JWT token authentication
- Role-based authorization
- Input validation and sanitization
- CORS protection

## Development

### Running in Development Mode
```bash
go run main.go
```

### Building for Production
```bash
go build -o quickdesk-server main.go
```

### Environment Variables
All configuration is done through environment variables. See `.env.example` for all available options.

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
