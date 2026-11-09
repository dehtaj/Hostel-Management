-- SmartHostel FINAL ONE-FILE DATABASE SETUP
-- ================================================================
-- SAFE FRESH DATABASE SETUP
-- This file NEVER drops or deletes an existing database.
-- If an old SmartHostel database exists, back it up first and create a new
-- empty database (or choose a new DB_NAME in .env) before running this file.
-- See BACKUP_BEFORE_RESET.md for the data-preservation workflow.
-- ================================================================
CREATE DATABASE IF NOT EXISTS smarthostel_management
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smarthostel_management;

SET FOREIGN_KEY_CHECKS=0;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','student','warden','accountant','maintenance') NOT NULL DEFAULT 'student',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE,
    student_code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    course VARCHAR(50),
    year VARCHAR(10),
    phone VARCHAR(15),
    email VARCHAR(100),
    lifecycle_status ENUM('active','checked_out','transferred','inactive') NOT NULL DEFAULT 'active',
    checked_out_at DATETIME NULL,
    monthly_fee DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    CHECK (monthly_fee >= 0),
    archived_at DATETIME NULL,
    joined_on DATE DEFAULT (CURRENT_DATE),
    CONSTRAINT fk_students_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_students_lifecycle (lifecycle_status)
) ENGINE=InnoDB;

CREATE TABLE floors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    floor_name VARCHAR(80) NOT NULL,
    floor_number INT NOT NULL,
    building_name VARCHAR(100) NOT NULL DEFAULT 'Main',
    status ENUM('active','maintenance') NOT NULL DEFAULT 'active',
    UNIQUE KEY uq_floor (building_name, floor_number)
) ENGINE=InnoDB;

CREATE TABLE rooms (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room_number VARCHAR(10) UNIQUE NOT NULL,
    room_type VARCHAR(30) DEFAULT 'Standard',
    capacity INT NOT NULL,
    occupied INT NOT NULL DEFAULT 0,
    block_name VARCHAR(80) NOT NULL DEFAULT 'Block A',
    floor_id INT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX idx_rooms_floor (floor_id),
    CONSTRAINT fk_rooms_floor FOREIGN KEY (floor_id) REFERENCES floors(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE beds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room_id INT NOT NULL,
    bed_number VARCHAR(20) NOT NULL,
    status ENUM('available','blocked','maintenance') NOT NULL DEFAULT 'available',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_room_bed (room_id, bed_number),
    CONSTRAINT fk_beds_room FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE allocations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    room_id INT NOT NULL,
    allocated_on DATE DEFAULT (CURRENT_DATE),
    vacated_on DATE NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_alloc_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    CONSTRAINT fk_alloc_room FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    INDEX idx_alloc_student_active (student_id, is_active),
    INDEX idx_alloc_room_active (room_id, is_active)
) ENGINE=InnoDB;

CREATE TABLE fees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    CHECK (amount > 0),
    due_date DATE NOT NULL,
    billing_month DATE NULL,
    bill_type ENUM('monthly','one_time') NOT NULL DEFAULT 'monthly',
    status ENUM('pending','paid','overdue') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_fees_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    UNIQUE KEY uq_fee_student_month (student_id, billing_month),
    INDEX idx_fees_student_billing_month (student_id, billing_month)
) ENGINE=InnoDB;

CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fee_id INT NOT NULL,
    amount_paid DECIMAL(10,2) NOT NULL,
    CHECK (amount_paid > 0),
    paid_on DATE NOT NULL DEFAULT (CURRENT_DATE),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    method VARCHAR(30) NOT NULL DEFAULT 'Cash',
    payment_reference VARCHAR(100) NULL,
    receipt_no VARCHAR(40) NULL UNIQUE,
    voided_at DATETIME NULL,
    voided_by INT NULL,
    void_reason VARCHAR(255) NULL,
    CONSTRAINT fk_payments_fee FOREIGN KEY (fee_id) REFERENCES fees(id) ON DELETE CASCADE,
    CONSTRAINT fk_payments_voided_by FOREIGN KEY (voided_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_payments_fee_active (fee_id, voided_at)
) ENGINE=InnoDB;

CREATE TABLE monthly_fee_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    old_amount DECIMAL(10,2) NOT NULL,
    new_amount DECIMAL(10,2) NOT NULL,
    effective_from DATE NOT NULL,
    changed_by INT NULL,
    changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_fee_history_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    CONSTRAINT fk_fee_history_user FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_fee_history_student_date (student_id, effective_from)
) ENGINE=InnoDB;

CREATE TABLE monthly_billing_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    billing_month DATE NOT NULL,
    due_day TINYINT UNSIGNED NOT NULL DEFAULT 10,
    generated_by INT NULL,
    generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_monthly_billing_month (billing_month),
    CONSTRAINT fk_billing_run_user FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE payment_orders (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    fee_id INT NOT NULL,
    gateway VARCHAR(30) NOT NULL DEFAULT 'razorpay',
    order_id VARCHAR(100) NOT NULL UNIQUE,
    payment_id VARCHAR(100) NULL UNIQUE,
    amount_paise BIGINT NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'INR',
    status ENUM('created','paid','failed') NOT NULL DEFAULT 'created',
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at DATETIME NULL,
    INDEX idx_payment_orders_fee (fee_id, status),
    CONSTRAINT fk_payment_orders_fee FOREIGN KEY (fee_id) REFERENCES fees(id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_orders_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE gateway_webhook_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    gateway_event_id VARCHAR(150) NOT NULL UNIQUE,
    event_type VARCHAR(100) NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_user_id INT NULL,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(80) NOT NULL,
    entity_id VARCHAR(80) NULL,
    details JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_entity (entity_type, entity_id),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE attendance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    date DATE NOT NULL,
    status ENUM('present','absent') NOT NULL,
    UNIQUE KEY unique_att (student_id, date),
    CONSTRAINT fk_att_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE complaints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    title VARCHAR(150) NOT NULL,
    description TEXT,
    priority ENUM('low','medium','high') DEFAULT 'medium',
    status ENUM('pending','in_progress','resolved') DEFAULT 'pending',
    deleted_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_complaint_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE visitors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    visitor_name VARCHAR(100) NOT NULL,
    purpose VARCHAR(150),
    student_id INT NOT NULL,
    check_in DATETIME DEFAULT CURRENT_TIMESTAMP,
    check_out DATETIME NULL,
    CONSTRAINT fk_visitor_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE leave_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT NOT NULL,
    status ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
    deleted_at DATETIME NULL,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_leave_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE RESTRICT,
    CONSTRAINT fk_leave_reviewer FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    CHECK (end_date >= start_date)
) ENGINE=InnoDB;

CREATE TABLE gate_passes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    destination VARCHAR(180) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    out_time DATETIME NOT NULL,
    expected_return DATETIME NOT NULL,
    actual_return DATETIME NULL,
    status ENUM('pending','approved','rejected','out','returned','cancelled') NOT NULL DEFAULT 'pending',
    deleted_at DATETIME NULL,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_gate_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE RESTRICT,
    CONSTRAINT fk_gate_reviewer FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    CHECK (expected_return > out_time)
) ENGINE=InnoDB;

SET FOREIGN_KEY_CHECKS=1;

SET FOREIGN_KEY_CHECKS=1;

-- Final sanity check: this should return the complete SmartHostel table list.
SELECT TABLE_NAME
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = DATABASE()
ORDER BY TABLE_NAME;
