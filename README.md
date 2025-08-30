# 🛡️ CyberGuard AI - Advanced Fraud Detection System

An advanced AI/ML-powered web application that detects and categorizes fraudulent online content using Google Cloud's Gemini API with a stunning glassmorphism interface.

## ✨ Features

- **🌐 Website Threat Analysis**: Detects fraudulent/phishing websites by analyzing URLs
- **📱 Mobile App Security Scan**: Identifies fake or malicious mobile applications  
- **🤖 AI-Powered Detection**: Uses Google Gemini AI for intelligent fraud analysis
- **💎 Glassmorphism UI**: Modern, beautiful interface with video background
- **⚡ Real-time Results**: Instant analysis with detailed explanations
- **🎥 Dynamic Background**: Video background with transparency effects
- **✨ Animated UI**: Floating particles and smooth animations

## 🚀 Setup Instructions

### Backend Setup
1. Navigate to the `backend` folder
2. Install dependencies: `pip install -r requirements.txt`
3. Start the server: `python app.py` or run `start_backend.bat`
4. Backend will be available at `http://localhost:5000`

### Frontend Setup
1. Navigate to the `frontend` folder
2. Open `index.html` in your web browser
3. Or serve it using a simple HTTP server

## 🔧 Google Cloud API Setup (Optional)

### Current Status
- ✅ **Demo Mode**: System works with simulated AI responses
- ⚠️ **Full AI Mode**: Requires Google Cloud API activation

### To Enable Full AI Analysis:

1. **Enable the Generative Language API**:
   - Visit: https://console.developers.google.com/apis/api/generativelanguage.googleapis.com/overview?project=1034250232006
   - Click "Enable" button
   - Wait a few minutes for activation

2. **Alternative**: Create a new Google Cloud project:
   - Go to https://console.cloud.google.com/
   - Create a new project
   - Enable the Generative Language API
   - Get a new API key
   - Replace the API key in `backend/app.py`

### API Error Resolution
If you see "API Error: 403 - SERVICE_DISABLED":
- The system automatically falls back to demo mode
- You'll still get detailed fraud analysis (simulated)
- Follow the steps above to enable full AI mode

## 🎨 UI Features

### Glassmorphism Design
- Translucent glass-like cards with blur effects
- Gradient backgrounds and smooth animations
- Video background with opacity controls
- Floating particle animations

### Advanced Effects
- **Backdrop Blur**: Modern glass morphism effect
- **Gradient Text**: Colorful animated text effects  
- **Hover Animations**: Interactive card transformations
- **Loading Spinners**: Elegant loading indicators
- **Responsive Design**: Works on all screen sizes

## 🔍 Usage

1. **Start the Backend**: Run the Flask server first
2. **Open Frontend**: Open `index.html` in your browser
3. **Analyze Content**:
   - **Website Analysis**: Enter a suspicious URL
   - **App Analysis**: Enter mobile app details
4. **View Results**: Get AI-powered analysis with risk assessment

## 📡 API Endpoints

- `GET /` - Health check endpoint
- `POST /analyze/website` - Analyze website for fraud
- `POST /analyze/app` - Analyze mobile app for fraud

## 🛠️ Technology Stack

- **Backend**: Python, Flask, Google Gemini AI, Flask-CORS
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **UI Framework**: Custom Glassmorphism CSS
- **AI/ML**: Google Cloud Generative Language API
- **Video**: HTML5 Video Background

## 🎥 Video Background

The application features a dynamic video background:
- **File**: `frontend/background-video.mp4`
- **Effect**: 30% opacity with overlay gradients
- **Loop**: Continuous playback
- **Responsive**: Scales to all screen sizes

## 🔒 Security Notes

- API key is embedded for demo purposes
- In production, use environment variables
- Implement proper API key management
- Use HTTPS in production deployment

## 🚨 Demo Mode Features

When the Google API is not enabled, the system provides:
- Realistic fraud analysis simulations
- Risk level assessments (Low/Medium/High)
- Detailed explanation of analysis process
- Educational content about fraud detection
- All UI features remain fully functional

## 🎯 Key Improvements

### Backend Enhancements
- ✅ Graceful API error handling
- ✅ Fallback analysis system
- ✅ Enhanced logging and debugging
- ✅ CORS support for all origins

### Frontend Upgrades
- ✅ Stunning glassmorphism design
- ✅ Video background integration
- ✅ Floating particle animations
- ✅ Advanced CSS effects and transitions
- ✅ Responsive mobile design
- ✅ Professional loading indicators

## 📱 Responsive Design

The interface automatically adapts to:
- **Desktop**: Full-width grid layout
- **Tablet**: Responsive card arrangement  
- **Mobile**: Single-column stacked layout
- **Small screens**: Optimized font sizes and spacing

## 🎨 Color Scheme

- **Primary**: Deep purple gradients (#667eea to #764ba2)
- **Background**: Dark blue theme (#0f0f23)
- **Glass**: Translucent white overlays (10-15% opacity)
- **Accents**: Green for success, red for errors
- **Text**: White with various opacity levels

Your AI-powered fraudulent content detection system is now ready with a professional, modern interface! 🚀
