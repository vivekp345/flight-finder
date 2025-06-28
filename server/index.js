// server/index.js

import express from 'express';
// import bodyParser from 'body-parser'; // Removed: express has built-in parsers
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'; // Import jsonwebtoken
import dotenv from 'dotenv'; // Import dotenv
import { User, Booking, Flight } from './schemas.js';

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json()); // Built-in Express JSON parser
app.use(express.urlencoded({ extended: true })); // Built-in Express URL-encoded parser
app.use(cors());

// --- Database Connection ---
const PORT = process.env.PORT || 6001; // Use PORT from .env or default to 6001
const MONGO_URI = process.env.MONGO_URI; // Use MONGO_URI from .env

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log(`MongoDB connected successfully!`);
    // Start listening for requests ONLY after DB connection is established
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
})
.catch((e) => console.log(`Error in DB connection: ${e}`));


// --- Middleware for JWT Authentication (Reusable) ---
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; // Attach user payload (id, usertype, approval) to request
        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Middleware for Admin Authorization
const adminAuth = (req, res, next) => {
    if (req.user.usertype !== 'admin') {
        return res.status(403).json({ message: 'Access denied: Admin role required' });
    }
    next();
};

// Middleware for Flight Operator Authorization
const flightOperatorAuth = (req, res, next) => {
    if (req.user.usertype !== 'flight-operator' || req.user.approval !== 'approved') {
        return res.status(403).json({ message: 'Access denied: Approved Flight Operator role required' });
    }
    next();
};


// --- API Routes ---

// Register User
app.post('/register', async (req, res) => {
    const { username, email, usertype, password } = req.body;
    let approval = 'approved'; // Default for user/admin

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email.' });
        }

        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({ message: 'Username already taken.' });
        }

        if (usertype === 'flight-operator') {
            approval = 'not-approved'; // Flight operators need approval
        } else if (usertype !== 'user' && usertype !== 'admin') {
             return res.status(400).json({ message: 'Invalid usertype. Must be user, admin, or flight-operator.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username, email, usertype, password: hashedPassword, approval
        });
        const userCreated = await newUser.save();

        // Generate JWT Token
        const payload = {
            user: {
                id: userCreated._id,
                usertype: userCreated.usertype,
                approval: userCreated.approval
            }
        };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err;
                res.status(201).json({ message: 'Registration successful!', token, user: userCreated });
            }
        );

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server Error during registration.' });
    }
});

// Login User
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check if flight operator is approved
        if (user.usertype === 'flight-operator' && user.approval === 'not-approved') {
            return res.status(403).json({ message: 'Flight operator account is not yet approved.' });
        }

        // Generate JWT Token
        const payload = {
            user: {
                id: user._id,
                usertype: user.usertype,
                approval: user.approval
            }
        };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ message: 'Login successful!', token, user });
            }
        );

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server Error during login.' });
    }
});

// Approve flight operator (Admin Only)
app.post('/approve-operator', authMiddleware, adminAuth, async (req, res) => { // Protected
    const { id } = req.body;
    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.usertype !== 'flight-operator') {
            return res.status(400).json({ message: 'Only flight operators can be approved.' });
        }
        user.approval = 'approved';
        await user.save();
        res.json({ message: 'Flight operator approved!', user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
});

// Reject flight operator (Admin Only)
app.post('/reject-operator', authMiddleware, adminAuth, async (req, res) => { // Protected
    const { id } = req.body;
    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.usertype !== 'flight-operator') {
            return res.status(400).json({ message: 'Only flight operators can be rejected.' });
        }
        user.approval = 'rejected';
        await user.save();
        res.json({ message: 'Flight operator rejected!', user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
});

// Fetch a single user (Admin/Self)
app.get('/fetch-user/:id', authMiddleware, async (req, res) => { // Protected
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        // Allow user to fetch their own profile, or admin to fetch any
        if (req.user.id !== req.params.id && req.user.usertype !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to view this user.' });
        }
        res.json(user);
    } catch (err) {
        console.error(err);
        if (err.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid User ID.' });
        }
        res.status(500).json({ message: 'Server Error' });
    }
});

// Fetch all users (Admin Only)
app.get('/fetch-users', authMiddleware, adminAuth, async (req, res) => { // Protected
    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
});


// Add flight (Flight Operator and Admin Only)
app.post('/add-flight', authMiddleware, flightOperatorAuth, async (req, res) => { // Protected
    const { flightName, flightId, origin, destination, departureTime,
        arrivalTime, basePrice, totalSeats, journeyDate } = req.body; // Added journeyDate for clarity and consistency

    try {
        // You might want to check for existing flightId for uniqueness
        const flight = new Flight({
            flightName, flightId, origin, destination,
            departureTime, arrivalTime, basePrice, totalSeats,
            journeyDate: new Date(journeyDate), // Ensure journeyDate is Date object
            availableSeats: totalSeats // Initialize available seats
        });
        await flight.save(); // Await the save operation
        res.status(201).json({ message: 'Flight added successfully!', flight }); // Return the created flight
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error adding flight.' });
    }
});

// Update flight (Flight Operator and Admin Only)
app.put('/update-flight', authMiddleware, flightOperatorAuth, async (req, res) => { // Protected
    const { _id, flightName, flightId, origin, destination,
        departureTime, arrivalTime, basePrice, totalSeats, journeyDate } = req.body;

    try {
        const flight = await Flight.findById(_id);
        if (!flight) {
            return res.status(404).json({ message: 'Flight not found.' });
        }

        // Only allow update by the flight operator or admin
        // (Assuming you'd want to track which flight operator added a flight,
        // but based on current schema, we can't tie a flight to an operator.
        // For simplicity, any approved operator/admin can update any flight for now.)

        flight.flightName = flightName || flight.flightName;
        flight.flightId = flightId || flight.flightId;
        flight.origin = origin || flight.origin;
        flight.destination = destination || flight.destination;
        flight.departureTime = departureTime || flight.departureTime;
        flight.arrivalTime = arrivalTime || flight.arrivalTime;
        flight.basePrice = basePrice || flight.basePrice;
        flight.totalSeats = totalSeats || flight.totalSeats;
        if (journeyDate) flight.journeyDate = new Date(journeyDate); // Update date if provided

        // Re-calculate availableSeats if totalSeats changed
        // This is tricky. If totalSeats decreases below current bookings, it's an issue.
        // For simplicity, let's just update totalSeats. Real app needs more logic.
        // flight.availableSeats = flight.totalSeats - (total_booked_seats_for_this_flight); // This requires fetching all bookings for this flight

        await flight.save();
        res.json({ message: 'Flight updated successfully!', flight });
    } catch (err) {
        console.error(err);
        if (err.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid Flight ID.' });
        }
        res.status(500).json({ message: 'Server Error updating flight.' });
    }
});

// Fetch all flights (Public)
app.get('/fetch-flights', async (req, res) => {
    try {
        const flights = await Flight.find();
        res.json(flights);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error fetching flights.' });
    }
});

// Fetch a single flight (Public)
app.get('/fetch-flight/:id', async (req, res) => {
    try {
        const flight = await Flight.findById(req.params.id);
        if (!flight) {
            return res.status(404).json({ message: 'Flight not found.' });
        }
        res.json(flight);
    } catch (err) {
        console.error(err);
        if (err.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid Flight ID.' });
        }
        res.status(500).json({ message: 'Server Error fetching flight.' });
    }
});

// Fetch all bookings (Admin Only)
app.get('/fetch-bookings', authMiddleware, adminAuth, async (req, res) => { // Protected
    try {
        const bookings = await Booking.find()
            .populate('user', 'username email usertype') // Assuming 'user' field in Booking refers to User model
            .populate('flight', 'flightName origin destination departureTime journeyDate'); // Assuming 'flight' field in Booking refers to Flight model
        res.json(bookings);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error fetching bookings.' });
    }
});

// Book ticket (User Only)
app.post('/book-ticket', authMiddleware, async (req, res) => { // Protected
    const { flightId, passengers, seatClass } = req.body;
    const userId = req.user.id; // Get user ID from JWT payload

    try {
        // 1. Fetch Flight to get details and check availability
        const flight = await Flight.findById(flightId);
        if (!flight) {
            return res.status(404).json({ message: 'Flight not found.' });
        }

        const numSeatsToBook = passengers.length;
        if (flight.availableSeats < numSeatsToBook) {
            return res.status(400).json({ message: `Not enough seats available. Only ${flight.availableSeats} seats left.` });
        }

        // 2. Calculate Price (basic: passengers * basePrice)
        const totalPrice = numSeatsToBook * flight.basePrice;

        // 3. Generate seat numbers (based on existing logic)
        // Find existing bookings for this flight and seat class
        const existingBookingsInClass = await Booking.find({ flight: flightId, seatClass: seatClass });
        const numBookedSeatsInClass = existingBookingsInClass.reduce((acc, booking) => acc + booking.passengers.length, 0);

        let seatsAssigned = [];
        const seatCode = { 'economy': 'E', 'premium-economy': 'P', 'business': 'B', 'first-class': 'A' };
        let coachPrefix = seatCode[seatClass];

        for (let i = 0; i < numSeatsToBook; i++) {
            seatsAssigned.push(`${coachPrefix}-${numBookedSeatsInClass + i + 1}`);
        }

        // 4. Create Booking
        const newBooking = new Booking({
            user: userId, // Link to User model
            flight: flightId, // Link to Flight model
            flightName: flight.flightName,
            flightId: flight.flightId, // Use the flight's flightId (string)
            departure: flight.departureTime, // Assuming this means actual departure time from flight
            destination: flight.destination,
            email: req.user.email, // Assuming user email is in JWT or fetched from DB
            mobile: req.body.mobile || 'N/A', // Assuming mobile might come from request body or user profile
            passengers: passengers,
            totalPrice: totalPrice,
            journeyDate: flight.journeyDate, // Use flight's journeyDate
            journeyTime: flight.departureTime, // Assuming this is the departure time
            seatClass: seatClass,
            seats: seatsAssigned.join(', '), // Store as comma-separated string
            bookingStatus: 'confirmed',
            bookingDate: new Date() // Current date/time
        });
        await newBooking.save();

        // 5. Update available seats on the Flight
        flight.availableSeats -= numSeatsToBook;
        await flight.save();

        res.status(201).json({ message: 'Booking successful!', booking: newBooking });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error during booking.' });
    }
});

// Cancel ticket (User who owns it, or Admin)
app.put('/cancel-ticket/:id', authMiddleware, async (req, res) => { // Protected
    const bookingId = req.params.id;
    try {
        const booking = await Booking.findById(bookingId);
        if (!booking) {
            return res.status(404).json({ message: 'Booking not found.' });
        }

        // Check if user is the owner OR if user is an admin
        if (booking.user.toString() !== req.user.id && req.user.usertype !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to cancel this booking.' });
        }

        if (booking.bookingStatus === 'cancelled') {
            return res.status(400).json({ message: 'Booking is already cancelled.' });
        }

        booking.bookingStatus = 'cancelled';
        await booking.save();

        // Restore seats to the flight's availableSeats
        const flight = await Flight.findById(booking.flight); // Use flight ID from booking
        if (flight) {
            flight.availableSeats += booking.passengers.length; // Add back number of passengers/seats booked
            await flight.save();
        }

        res.json({ message: 'Booking cancelled successfully!', booking });
    } catch (err) {
        console.error(err);
        if (err.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid Booking ID.' });
        }
        res.status(500).json({ message: 'Server Error during cancellation.' });
    }
});

// Basic route for root URL (optional)
app.get('/', (req, res) => {
    res.send('Flight Booking API is running!');
});