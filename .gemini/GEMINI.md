**Agent Operating Principles**

Your primary directive is to act as a critical and skeptical partner. The goal is a top-notch, production-ready project and architecture.

*   **Challenge Ideas**: Scrutinize and challenge my proposals. Focus on solving the real, underlying problem effectively.
*   **Root-Cause Debugging**: When debugging, do not propose solutions based on guesswork. Drive towards the root cause until we are 100% certain before implementing a fix.
*   **Clarify Ambiguity**: If a request is ambiguous or unclear, you must ask for clarification to confirm the desired behavior or outcome before proceeding.

---

Below is the detailed context for the project:

# Gemini Project Context: Personal Finance Manager

This document is the primary context for the AI agent working on this project. It contains high-level overviews, development standards, and critical implementation nuances to ensure all modifications are consistent, safe, and aligned with the project's design.

## 1. Project Overview

*   **Purpose**: To offer an effective and highly flexible finance tracking solution for individuals, freelancers, non-profits, and small businesses. The goal is to be a powerful, structured alternative to spreadsheets, not to compete with full-fledged enterprise accounting software.
*   **Core Technologies**:
    *   **Backend**: Django, Django REST Framework (DRF), PostgreSQL.
    *   **Frontend**: React, Vite, Redux Toolkit.
    *   **Infrastructure**: Docker.
*   **Core Architectural Pattern**: The backend follows a "Thin Views, Fat Services" pattern. API Views are lightweight and delegate all business logic to a dedicated **Service Layer** (`/backend/finance/services/`). This ensures logic is centralized, reusable, and easy to test.

---

## 2. Agent Development Guidelines

These are the mandatory standards for all code generation and modification.

*   **Code Quality**: All generated code must be of high quality, well-documented, and include comprehensive logging, consistent with the existing codebase.
*   **Language**: All code, comments, and documentation must be in **English**, regardless of the prompt's language.
*   **Frontend Localization**:
    *   The frontend is tri-lingual: English (en), Czech (cs), and Slovak (sk).
    *   Translation logic is handled within the React application.
    *   **Rule**: Any new user-facing text added to the frontend must include translation keys and values for all three languages.

---

## 3. Critical Business Logic & Implementation Nuances

This section contains the most important, non-obvious rules that are critical for making correct code changes.

### 3.1. Permissions & The Hierarchy of Power

Permissions are cascading. A user's power is determined by their highest role.

1.  **`Superuser`**: Highest authority (`is_superuser`). Has unrestricted system access. The only role that can assign a `WorkspaceAdmin`.
2.  **`WorkspaceAdmin`**: A delegate of the Superuser, assigned to manage a *specific* workspace.
    *   **Crucial**: This is **not a membership role** and is stored in a separate `WorkspaceAdmin` model.
    *   Their privileges within the assigned workspace are equal to or **greater than** the `Owner` (e.g., they can change the workspace owner).
3.  **`Owner`**: The highest *membership* role within a workspace. Can manage members and settings but can be superseded by an Admin or Superuser.
4.  **`Editor`**: A standard member with write access.
5.  **`Viewer`**: A standard member with read-only access.

### 3.2. Data Integrity & Safety Rules

*   **Strict Transaction Ownership**: A user can **only modify or delete their own** transactions. Even a workspace `Owner` cannot edit another member's transactions directly. This must be done via admin impersonation.
*   **Safe Category Deletion (Soft Delete)**: To preserve historical data, the system **prevents the deletion of a category that is in use**.
    *   If a used category is "deleted", it is **soft-deleted** by setting its `is_active` flag to `False`. This archives it and removes it from UI selection.
    *   If a category is unused, it is permanently **hard-deleted**.
*   **Leaf Category Movement Lock**: A Level 5 (leaf) category **cannot be moved** to a new parent if it has already been used in transactions. This preserves the integrity of historical reports.
*   **Workspace Hard Deletion Safety**: Permanently deleting a workspace is intentionally difficult:
    *   An **Owner** can only do so if they are the **last member remaining**. They must also confirm by typing the exact workspace name.
    *   An **Admin/Superuser** can bypass the member check but must provide a special confirmation code (`admin-delete-<workspace_id>`) to proceed.

### 3.3. Financial Calculation Logic

*   **Exchange Rate Fallback**: Currency conversion uses the most recent exchange rate available **on or before** the transaction's date. It never uses a future rate. If no prior rate exists, the conversion fails.
*   **Conditional Recalculation**: Currency conversion for a transaction is only re-triggered on a save if `original_amount`, `original_currency`, or `date` has changed. This optimizes updates.

### 3.4. Automatic & Latent Behaviors

*   **Formal Accounting Mode (Latent Feature)**: `WorkspaceSettings` has an `accounting_mode` flag. While currently unused, it is intended for future reporting features to differentiate between cash-flow (`expense`/`income`) and formal accounting (`cost`/`revenue`) based on `CategoryProperty` models.
*   **Automatic Owner Sync**: The `Workspace` model's `save()` method ensures its `owner` always has the 'owner' role in `WorkspaceMembership`, preventing data inconsistency.
*   **Automatic Tag Lowercasing**: All tags are converted to lowercase on save, making them case-insensitive.
*   **Automatic Month Field**: The `Transaction` model's `save()` method automatically populates a `month` field (by setting the day to 1) for efficient monthly reporting queries.
*   **Automatic Draft Deletion**: Successfully creating or updating a transaction automatically deletes the corresponding temporary `TransactionDraft`.

---

## 4. API Endpoint Overview

The API is structured around RESTful resources, primarily scoped by workspace. Key endpoints include:

*   `/api/workspaces/`: Manage workspaces and members.
*   `/api/transactions/`: CRUD for transactions.
*   `/api/workspaces/{id}/transactions/bulk-sync/`: Atomic create, update, and delete for transactions.
*   `/api/workspaces/{id}/categories/{type}/sync/`: Atomic create, update, and delete/deactivate for categories.
*   `/api/user-settings/` & `/api/workspace-settings/`: Manage configuration.
*   `/api/transaction-drafts/`: Manage temporary work-in-progress transactions.

---
## 5. Codebase & Logic Map

To accelerate development and ensure consistency, here is a map of where key logic is located in the backend.

*   **Django Project & Core Configuration**: `backend/core/`
    *   **Settings**: `backend/core/settings/` - Environment-specific settings (dev, production). `base.py` contains the shared configuration.
    *   **Root URLs**: `backend/core/urls.py` - The main URL router for the entire application.

*   **User Management**: `backend/users/`
    *   **Model**: `models.py` defines the `CustomUser` model.
    *   **API Views & Endpoints**: `views.py` and `urls.py` handle user-related API requests (e.g., registration, user details).
    *   **Serialization**: `serializers.py` controls how user data is converted to and from JSON.

*   **Core Finance Application**: `backend/finance/`
    *   **Business Logic (Service Layer)**: `services/` - **This is the most important directory.** All business logic (creating transactions, calculating totals, managing workspaces) is encapsulated in service modules here.
        *   Example: `transaction_service.py` contains all logic for handling transaction data.
    *   **API Views (Thin Views)**: `views.py` - Contains the DRF `ViewSet` classes. These should be lightweight, handling only request/response, authentication, and permissions. They call the appropriate service modules to perform business logic.
    *   **Data Models**: `models.py` - Defines the core database tables like `Workspace`, `Transaction`, `Category`, and `Tag`.
    *   **API Endpoints**: `urls.py` - Defines the URL routes for the finance API.
    *   **Serializers**: `serializers.py` - Manages the serialization of finance models.
    *   **Custom Permissions**: `permissions.py` - Defines rules for who can access or modify data.
    *   **Reusable View Logic**: `mixins/` - Contains mixins used by the views to provide common functionality (e.g., getting the workspace context).

---
## 6. Testing Strategy

Maintaining high code quality and stability is critical. All new features or bug fixes must include comprehensive tests.

*   **Test Runner**: The project uses `pytest`.
*   **Test Data**: The `factory-boy` library is used to create test model instances. Factories are defined in `backend/finance/tests/factories.py`. Use these factories to generate consistent test data.

### 6.1. Test Structure

Tests are located within each app's `tests` directory (e.g., `backend/finance/tests/`) and are organized into two primary types:

*   **Unit Tests**: `tests/unit/`
    *   **Purpose**: To test individual components in isolation (e.g., a single function in a service, a method on a model, or a serializer's validation).
    *   **File Naming**: Unit test files should mirror the module they are testing.
        *   Logic in `services/category_service.py` is tested in `tests/unit/test_service_category.py`.
        *   Logic in `models.py` is tested in `tests/unit/test_models.py`.
    *   **Guideline**: When you add a function to a service, add a corresponding unit test in the appropriate test file. These tests should not make database calls if possible (mocking dependencies) unless testing model-specific logic.

*   **Integration / API Tests**: `tests/integration/`
    *   **Purpose**: To test the complete request-response cycle of the API endpoints. They verify that the views, serializers, services, and models all work together correctly.
    *   **File Naming**: API tests are primarily located in `tests/integration/test_apis.py`.
    *   **Guideline**: When adding a new API endpoint or modifying an existing one, you must add or update the corresponding integration tests. These tests use Django's test client to make HTTP requests to the API and assert the correctness of the response (status code, JSON data, etc.).

### 6.2. General Rules

*   When you add a new feature, write both unit tests for the business logic (in the service layer) and integration tests for the API endpoint.
*   When you fix a bug, first write a test that fails because of the bug, and then apply the fix to make the test pass.
*   If you remove a feature or refactor code, ensure you remove or update any obsolete tests to keep the test suite clean.
