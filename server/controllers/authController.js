import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken"; 

import userModel from '../models/userModel.js';
import transporter from '../nodemailer.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: "Missing Details" });
    }

    try {
        // Check if user already exists
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.json({ success: false, message: "User exists with the emailId" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });

        // Save user to DB
        await user.save();

        // Generate JWT Token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        // Set token in cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        });

         //Sending welcome email 
    const mailOption = {
        from : process.env.SENDER_EMAIL,
        to : email,
        subject : "Welcome to My Website",
        text: `Welcome to my Website. Your account has been created with the emailid : ${email}`
    }
    
    await transporter.sendMail(mailOption) // Sends the email

        return res.json({ success: true, message :"Registered Successfully" });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};

export const login =  async (req,res) => {
const {email, password} = req.body 

if(!email || !password){
return res.json({sucess: false, message: "Email and password are required"})
}


try {
    const user = await userModel.findOne({email});
    if(!user){
        return res.json({success: false, message: 'Invalid email'})
    }

    const isMatch = await bcrypt.compare(password, user.password)

   if(!isMatch){
        return res.json({success: false, message: 'Invalid password'})
    }

    const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn : '7d'}) 

    res.cookie('token' , token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        maxAge : 7 * 24 * 60 * 60 * 1000 // Converting in milliseconds
    });

   

     return res.json({success: true, message: "Logged In Successfully"})

} catch (error) {
    return res.json({success: false, message: error.message})
}
} 

export const logout = async (req,res) => {
    try {
        res.clearCookie('token' , {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: "Logged Out"})
    } catch (error) {
        return res.json({success:false , message: error.message})
    }
}


// Function for Sending  verification  OTP to Email
export const sendverifyOtp = async (req,res) => {
try {
    const {userId} = req.body // userId is recieved by token. Token is stored in cookies . 
                              // Need a middleware to get the cookie and that cookie will send a response as userId

    const user = await userModel.findById(userId) //Find whether the user exists with thee  userId

    if(user.isAccountVerified){
        return res.json({ success : false, message: "Account Already verified"})
 } // Checking if the user account is already authenticated

    const otp = String(Math.floor(100000 + Math.random() * 900000)) // Javascript random method to generate OTP

    user.verifyOtp = otp;
   
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000 // Otp expiry timr converted in millseconds
   
    await user.save(); // Storing the verifyOtpExpireAt field to the mongodb database

    const mailOption = {
        from : process.env.SENDER_EMAIL,
        to : user.email,
        subject : "Account Verfication OTP ",
        text: `Yor OTP is : ${otp}. Verify your account using this OTP.`
    }
    
    await transporter.sendMail(mailOption)

    return res.json({success : true, message: "Verification OTP Sent on Email"})
} catch (error) {
    res.json({success: false, message:"Not Authorized Login"})
}
}

export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: "Missing details" });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        // Convert otp to string for correct comparison
        if (!user.verifyOtp || user.verifyOtp !== String(otp)) {
            return res.json({ success: false, message: " OTP" });
        }

        // Ensure OTP is not expired
        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP has expired" });
        }

        // Mark account as verified
        user.isAccountVerified = true;
        user.verifyOtp = null; // Clear OTP
        user.verifyOtpExpireAt = null; // Reset expiry

        await user.save();

        return res.json({ success: true, message: "Email verified successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};


//Check whether user is authenticated or not
export const isAuthenticated = async (req,res) => {
    try {
        return res.json({success: true})
    } catch (error) {
       return  res.json({ success :false , message: error.message})
    }
} 

//Send Password Reset
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: "Email is required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); // Generate 6-digit OTP

        // ✅ Store OTP in resetOtp field (not verifyOtp)
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes

        await user.save(); // Save to database

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Password Reset OTP",
            text: `Your OTP for resetting your password is ${otp}. Use this OTP to reset your password.`
        };

        await transporter.sendMail(mailOption);

        return res.json({ success: true, message: 'OTP sent to your email' });

    } catch (error) {
        console.error("Error sending reset OTP:", error);
        return res.json({ success: false, message: "Something went wrong while sending OTP" });
    }
}


//Reset User password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Email, OTP, and new password are required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        console.log("Stored OTP:", user.resetOtp);
        console.log("Entered OTP:", otp);

        if (!user.resetOtp || user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        res.clearCookie("token"); // ✅ Clear token if previously logged in

        return res.json({ success: true, message: "Password has been reset successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};
