-- Migration: Add password_hash column to users table
-- Run this in Supabase SQL Editor

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

SELECT 'password_hash column added to users table' as status;
