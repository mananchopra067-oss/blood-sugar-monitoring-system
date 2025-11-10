const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db/connection');

const router = express.Router();

// 1. Register new patient account
router.post('/register', async (req, res) => {
  const { healthcare_number, name, email, password, phone, dob } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await pool.getConnection();
    await conn.beginTransaction();

    const [userResult] = await conn.execute(
      `INSERT INTO User (Name, Email, Password_Hash, Phone, Role, Created_At, Status)
       VALUES (?, ?, ?, ?, 'Patient', NOW(), 'Active')`,
      [name, email, hashedPassword, phone]
    );

    const userId = userResult.insertId;

    await conn.execute(
      `INSERT INTO Patient (Patient_ID, Healthcare_Number, Date_Of_Birth)
       VALUES (?, ?, ?)`,
      [userId, healthcare_number, dob]
    );

    await conn.commit();
    conn.release();

    res.status(201).json({ success: true, user_id: userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// 2. User login (all user types)
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();
    const [users] = await conn.execute(`SELECT * FROM User WHERE Email = ?`, [email]);
    conn.release();

    if (users.length === 0) return res.status(404).json({ success: false, error: 'User not found' });

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.Password_Hash);
    if (!isMatch) return res.status(401).json({ success: false, error: 'Invalid password' });

    res.status(200).json({
      success: true,
      user_id: user.User_ID,
      role: user.Role,
      name: user.Name,
      email: user.Email,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

// 3. Get user profile by ID
router.get('/:id/profile', async (req, res) => {
  const user_id = req.params.id;

  try {
    const conn = await pool.getConnection();
    const [userRows] = await conn.execute(`SELECT * FROM User WHERE User_ID = ?`, [user_id]);

    if (userRows.length === 0) {
      conn.release();
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const user = userRows[0];
    let roleData = {};

    const roleTableMap = {
      Patient: 'Patient',
      Specialist: 'Specialist',
      Clinic_Staff: 'Clinic_Staff',
      Administrator: 'Administrator',
    };

    const roleTable = roleTableMap[user.Role];
    const [roleRows] = await conn.execute(`SELECT * FROM ${roleTable} WHERE ${roleTable}_ID = ?`, [user_id]);

    conn.release();
    roleData = roleRows[0];

    res.status(200).json({ success: true, user: { ...user, roleData } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Failed to fetch profile' });
  }
});

// 4. Update user profile
router.put('/:id/update', async (req, res) => {
  const user_id = req.params.id;
  const { name, email, phone, profile_image } = req.body;

  try {
    const conn = await pool.getConnection();

    // Check email uniqueness
    const [existing] = await conn.execute(
      `SELECT * FROM User WHERE Email = ? AND User_ID != ?`,
      [email, user_id]
    );
    if (existing.length > 0) {
      conn.release();
      return res.status(400).json({ success: false, error: 'Email already in use' });
    }

    await conn.execute(
      `UPDATE User SET Name = ?, Email = ?, Phone = ?, Profile_Image = ? WHERE User_ID = ?`,
      [name, email, phone, profile_image, user_id]
    );

    conn.release();
    res.status(200).json({ success: true, message: 'Profile updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Update failed' });
  }
});

// 5. Create specialist account (admin only)
router.post('/create-specialist', async (req, res) => {
  const { name, email, password, working_id, specialization } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await pool.getConnection();
    await conn.beginTransaction();

    const [userResult] = await conn.execute(
      `INSERT INTO User (Name, Email, Password_Hash, Role, Created_At, Status)
       VALUES (?, ?, ?, 'Specialist', NOW(), 'Active')`,
      [name, email, hashedPassword]
    );

    const userId = userResult.insertId;

    await conn.execute(
      `INSERT INTO Specialist (Specialist_ID, Working_ID, Specialization)
       VALUES (?, ?, ?)`,
      [userId, working_id, specialization]
    );

    await conn.commit();
    conn.release();

    res.status(201).json({ success: true, specialist_id: userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Specialist creation failed' });
  }
});

// 6. Create staff account (admin only)
router.post('/create-staff', async (req, res) => {
  const { name, email, password, working_id, department } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await pool.getConnection();
    await conn.beginTransaction();

    const [userResult] = await conn.execute(
      `INSERT INTO User (Name, Email, Password_Hash, Role, Created_At, Status)
       VALUES (?, ?, ?, 'Clinic_Staff', NOW(), 'Active')`,
      [name, email, hashedPassword]
    );

    const userId = userResult.insertId;

    await conn.execute(
      `INSERT INTO Clinic_Staff (Staff_ID, Working_ID, Department)
       VALUES (?, ?, ?)`,
      [userId, working_id, department]
    );

    await conn.commit();
    conn.release();

    res.status(201).json({ success: true, staff_id: userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Staff creation failed' });
  }
});

// 7. Delete user account (admin only)
router.delete('/:id/delete', async (req, res) => {
  const user_id = req.params.id;

  try {
    const conn = await pool.getConnection();

    const [userRows] = await conn.execute(`SELECT Role FROM User WHERE User_ID = ?`, [user_id]);
    if (userRows.length === 0) {
      conn.release();
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const role = userRows[0].Role;
    const roleTableMap = {
      Patient: 'Patient',
      Specialist: 'Specialist',
      Clinic_Staff: 'Clinic_Staff',
      Administrator: 'Administrator',
    };

    const roleTable = roleTableMap[role];
    await conn.execute(`DELETE FROM ${roleTable} WHERE ${roleTable}_ID = ?`, [user_id]);
    await conn.execute(`DELETE FROM User WHERE User_ID = ?`, [user_id]);

    conn.release();
    res.status(200).json({ success: true, message: 'User deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Deletion failed' });
  }
});

// 8. Get all users by role (for admin dashboard)
// router.get('/role/:role', async (req, res) => {
//   const role = req.params.role;

//   try {
//     const conn = await pool.getConnection();

//     const [users] = await conn.execute(`SELECT * FROM User WHERE Role = ?`, [role]);
//     const roleTableMap = {
//       Patient: 'Patient',
//       Specialist: 'Specialist',
//       Clinic_Staff: 'Clinic_Staff',
//       Administrator: 'Administrator',
//     };

//     const roleTable = roleTableMap[role];
//     const enrichedUsers = [];

//     for (const user of users) {
//       const [roleRows] = await conn.execute(
//         `SELECT * FROM ${roleTable} WHERE ${roleTable}_ID = ?`,
//         [user.User_ID]
//       );
//       enrichedUsers.push({ ...user, roleData: roleRows[0] });
//     }

//     conn.release();
//     res.status();