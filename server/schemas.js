// server/schemas.js

import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    usertype: { type: String, required: true },
    password: { type: String, required: true },
    approval: {type: String, default: 'approved'} // e.g., 'approved', 'not-approved', 'rejected'
});

// --- CORRECTED FLIGHT SCHEMA ---
const flightSchema = new mongoose.Schema({
    flightName: { type: String, required: true },
    flightId: { type: String, required: true }, // Unique identifier for the flight (e.g., AA123)
    origin: { type: String, required: true },
    destination: { type: String, required: true },
    departureTime: { type: String, required: true }, // e.g., "10:00 AM"
    arrivalTime: { type: String, required: true },   // e.g., "06:00 PM"
    basePrice: { type: Number, required: true },
    totalSeats: { type: Number, required: true },
    journeyDate: { type: Date, required: true }, // <--- ADDED: Date of the journey
    availableSeats: { type: Number, required: true } // <--- ADDED: Seats remaining for booking
});

const bookingSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'users', required: true }, // Note: ref 'users' matches model name for 'User'
    flight: { type: mongoose.Schema.Types.ObjectId, ref: 'Flight', required: true },
    flightName: {type: String, required: true},
    flightId: {type: String}, // Flight ID string from the Flight document
    departure: {type: String}, // e.g., "10:00 AM"
    destination: {type: String},
    email: {type: String},
    mobile: {type: String},
    seats: {type: String}, // Comma-separated string of seat numbers e.g. "E-1, E-2"
    passengers: [{ // Array of passenger details for this booking
        name: { type: String },
        age: { type: Number }
    }],
    totalPrice: { type: Number },
    bookingDate: { type: Date, default: Date.now }, // When the booking was made
    journeyDate: { type: Date }, // Date of the flight journey
    journeyTime: { type: String }, // Time of the flight journey (e.g., "10:00 AM")
    seatClass: { type: String}, // e.g., 'economy', 'business'
    bookingStatus: {type: String, default: "confirmed"} // e.g., 'confirmed', 'cancelled'
});

export const User = mongoose.model('users', userSchema); // Model name 'users' for collection
export const Flight = mongoose.model('Flight', flightSchema); // Model name 'Flight' for collection
export const Booking = mongoose.model('Booking', bookingSchema); // Model name 'Booking' for collection