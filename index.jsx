import React, { useState, useEffect, useRef, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged, signOut, createUserWithEmailAndPassword, signInWithEmailAndPassword } from 'firebase/auth';
import { getFirestore, doc, getDoc, setDoc, onSnapshot, collection, query, orderBy, addDoc, serverTimestamp, where, updateDoc, getDocs } from 'firebase/firestore';
import { LogOut, Hash, Phone, Loader, Users, MessageSquare, Mic, X, Send, UserCheck, Zap, Settings, Search, CheckCircle, UserPlus, LogIn } from 'lucide-react';

// --- Global Context and Initial Setup (Mandatory Variables) ---
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {}; // FIXED: Used __firebase_config instead of typo __firebase_firebaseConfig
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null; // Kept for reference, but usage is removed/modified

// --- Message Input Component ---
const MessageInput = React.memo(({ activeChat, messageInput, setMessageInput, handleSendMessage, partnerDisplayName }) => {
    
    // Check if the chat is active and if a call is ongoing to disable the input
    const isDisabled = activeChat?.callState === 'active';
    const isButtonDisabled = messageInput.trim() === '' || isDisabled;

    return (
        <form onSubmit={handleSendMessage} className="p-4 bg-gray-800 border-t border-gray-700 flex">
            <input
                type="text"
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                className="flex-1 p-3 bg-gray-600 text-white rounded-l-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 placeholder-gray-400"
                placeholder={`Message #${partnerDisplayName}...`}
                disabled={isDisabled}
            />
            <button
                type="submit"
                disabled={isButtonDisabled}
                className="p-3 bg-indigo-600 text-white rounded-r-lg hover:bg-indigo-700 transition duration-150 disabled:bg-gray-500 disabled:cursor-not-allowed flex items-center justify-center"
            >
                <Send size={24} />
            </button>
        </form>
    );
});

// --- Display Name Modal Component ---
const DisplayNameModal = ({ isEditingDisplayName, newDisplayName, setNewDisplayName, handleSetDisplayName, setIsEditingDisplayName }) => {
    if (!isEditingDisplayName) return null;

    return (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 p-4">
            <div className="bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-indigo-700">
                <h3 className="text-2xl font-bold text-indigo-400 mb-4">Set Your Unique Name</h3>
                <p className="text-gray-300 mb-6">Choose a name that's at least 3 characters long. This will be your permanent username.</p>
                
                <form onSubmit={handleSetDisplayName}>
                    <div className="mb-4">
                        <label htmlFor="displayName" className="block text-sm font-medium text-gray-400 mb-2">
                            New Username
                        </label>
                        <input
                            id="displayName"
                            type="text"
                            value={newDisplayName}
                            onChange={(e) => setNewDisplayName(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))} // Allow letters, numbers, and underscore
                            className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-indigo-500 focus:border-indigo-500"
                            placeholder="your_unique_tag"
                            minLength={3}
                            required
                        />
                    </div>
                    
                    <div className="flex justify-end space-x-3">
                        <button
                            type="button"
                            onClick={() => setIsEditingDisplayName(false)}
                            className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 transition"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition flex items-center"
                            disabled={newDisplayName.trim().length < 3}
                        >
                            <CheckCircle size={20} className="mr-1" /> Set Name
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

// --- Authentication Modal Component ---
const AuthModal = ({ isOpen, auth, onAuthSuccess, showSystemMessage, db, getUserProfileDoc, appId }) => { // Added appId
    const [isLoginMode, setIsLoginMode] = useState(true);
    const [authUsername, setAuthUsername] = useState(''); // Changed from authEmail
    const [authPassword, setAuthPassword] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);

    if (!isOpen) return null;

    const handleAuthAction = async (e) => {
        e.preventDefault();
        if (!auth || !db) return;
        setIsProcessing(true);

        // Sanitize and normalize username for internal use
        const normalizedUsername = authUsername.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
        if (normalizedUsername.length < 3) {
            showSystemMessage("Username must be at least 3 characters long.", 'error');
            setIsProcessing(false);
            return;
        }

        // Generate the synthetic email for Firebase Auth calls
        const syntheticEmail = `${normalizedUsername}@${appId}.com`; // CRITICAL CHANGE: Use username + appId for uniqueness

        try {
            if (isLoginMode) {
                // Login using the synthetic email
                await signInWithEmailAndPassword(auth, syntheticEmail, authPassword);
                showSystemMessage(`Welcome back, ${normalizedUsername}!`, 'success');

            } else {
                // Register

                // 1. Check if the chosen username is already in use in Firestore
                const usersRef = collection(db, 'artifacts', appId, 'public', 'data', 'userProfiles');
                const q = query(usersRef, where('displayName', '==', normalizedUsername));
                const querySnapshot = await getDocs(q);
                
                if (!querySnapshot.empty) {
                    showSystemMessage(`The username "${normalizedUsername}" is already taken.`, 'error');
                    setIsProcessing(false);
                    return;
                }

                // 2. Register with Firebase using the synthetic email
                const userCredential = await createUserWithEmailAndPassword(auth, syntheticEmail, authPassword);
                
                // 3. Create User Profile immediately after registration, using the username as displayName
                const profileRef = getUserProfileDoc(userCredential.user.uid);
                await setDoc(profileRef, {
                    uid: userCredential.user.uid,
                    displayName: normalizedUsername, // Use the actual username
                    lastActive: serverTimestamp(),
                });

                showSystemMessage(`Successfully registered! Welcome, ${normalizedUsername}!`, 'success');
            }
            onAuthSuccess();
        } catch (error) {
            console.error("Authentication error:", error.code, error.message);
            
            let message = "Authentication failed. Please check your credentials.";
            if (error.code === 'auth/email-already-in-use') {
                message = "That username is already taken. Try logging in or use a different username.";
            } else if (error.code === 'auth/weak-password') {
                message = "Password must be at least 6 characters long.";
            } else if (error.code === 'auth/invalid-email' || error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
                message = "Invalid username or password.";
            }
            
            showSystemMessage(message, 'error');
        } finally {
            setIsProcessing(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-90 flex items-center justify-center z-50 p-4">
            <div className="bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-purple-700">
                <h3 className="text-2xl font-bold text-purple-400 mb-6 text-center">
                    {isLoginMode ? 'Sign In to Dihcord' : 'Create an Account'}
                </h3>
                
                <form onSubmit={handleAuthAction}>
                    <div className="mb-4">
                        <label htmlFor="authUsername" className="block text-sm font-medium text-gray-400 mb-2">
                            Username
                        </label>
                        <input
                            id="authUsername"
                            type="text"
                            value={authUsername}
                            onChange={(e) => setAuthUsername(e.target.value)}
                            className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-purple-500 focus:border-purple-500"
                            placeholder="choose_a_tag"
                            minLength={3}
                            required
                        />
                    </div>
                    <div className="mb-6">
                        <label htmlFor="authPassword" className="block text-sm font-medium text-gray-400 mb-2">
                            Password
                        </label>
                        <input
                            id="authPassword"
                            type="password"
                            value={authPassword}
                            onChange={(e) => setAuthPassword(e.target.value)}
                            className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-purple-500 focus:border-purple-500"
                            placeholder="Minimum 6 characters"
                            minLength={6}
                            required
                        />
                    </div>
                    
                    <button
                        type="submit"
                        className="w-full px-4 py-3 bg-purple-600 text-white font-bold rounded-lg hover:bg-purple-700 transition flex items-center justify-center disabled:bg-gray-500"
                        disabled={isProcessing || authUsername.trim().length < 3 || authPassword.length < 6}
                    >
                        {isProcessing ? <Loader size={20} className="animate-spin mr-2" /> : (
                            <>
                                {isLoginMode ? <LogIn size={20} className="mr-2" /> : <UserPlus size={20} className="mr-2" />}
                                {isLoginMode ? 'Sign In' : 'Register'}
                            </>
                        )}
                    </button>
                </form>

                <div className="mt-4 text-center">
                    <button 
                        onClick={() => setIsLoginMode(!isLoginMode)} 
                        className="text-sm text-purple-400 hover:text-purple-300 transition"
                    >
                        {isLoginMode ? 'Need an account? Register now.' : 'Already have an account? Sign In.'}
                    </button>
                </div>
            </div>
        </div>
    );
};


// The main App component is exported by default.
const App = () => {
    // --- State Management ---
    const [db, setDb] = useState(null);
    const [auth, setAuth] = useState(null);
    const [userId, setUserId] = useState(null);
    const [isAuthReady, setIsAuthReady] = useState(false);
    const [isAnonymous, setIsAnonymous] = useState(false); 
    const [users, setUsers] = useState([]); 
    const [activeChat, setActiveChat] = useState(null); 
    const [chatMessages, setChatMessages] = useState([]); 
    const [messageInput, setMessageInput] = useState('');
    const [loading, setLoading] = useState(true);
    const [systemMessage, setSystemMessage] = useState({ visible: false, text: '' });
    
    // States for User Management and Search
    const [isEditingDisplayName, setIsEditingDisplayName] = useState(false);
    const [newDisplayName, setNewDisplayName] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    
    // Auth State
    const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);


    const messagesEndRef = useRef(null);

    // --- Firebase Initialization and Authentication (useEffect with []) ---
    useEffect(() => {
        if (Object.keys(firebaseConfig).length === 0) {
            console.error("Firebase config is missing.");
            setLoading(false);
            return;
        }

        try {
            const app = initializeApp(firebaseConfig);
            const authInstance = getAuth(app);
            const dbInstance = getFirestore(app);

            setDb(dbInstance);
            setAuth(authInstance);
            
            // --- CRITICAL CHANGE: ENFORCE NON-ANONYMOUS LOGIN ---
            const unsubscribe = onAuthStateChanged(authInstance, (user) => {
                if (user) {
                    // Check if the signed-in user is anonymous (e.g., from an environment token)
                    if (user.isAnonymous) {
                        console.log("Found unauthorized anonymous user. Signing out.");
                        // Signing out will trigger the listener again with user=null
                        signOut(authInstance).then(() => {
                            setLoading(false); 
                            setIsAuthReady(true);
                            setIsAuthModalOpen(true);
                        }).catch(e => {
                            console.error("Error during mandatory sign out:", e);
                            setLoading(false);
                        });
                        return; 
                    }
                    
                    // User is authenticated (non-anonymous)
                    setUserId(user.uid);
                    setIsAnonymous(false); 
                    setIsAuthReady(true);
                    setLoading(false);
                    setIsAuthModalOpen(false); // Close modal if authentication succeeds

                } else {
                    // User is null (not authenticated)
                    setUserId(null);
                    setIsAnonymous(false);
                    setLoading(false);
                    setIsAuthReady(true);
                    // Force AuthModal open if user is not authenticated
                    setIsAuthModalOpen(true);
                }
            });

            return () => unsubscribe();
        } catch (error) {
            console.error("Error initializing Firebase:", error);
            setLoading(false);
        }
    }, []);

    // Helper to scroll to the bottom of the chat
    useEffect(() => {
        if (messagesEndRef.current) {
            messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [chatMessages]);

    // Function to show transient system messages
    const showSystemMessage = useCallback((text, type = 'success') => {
        setSystemMessage({ visible: true, text, type });
        setTimeout(() => setSystemMessage({ visible: false, text: '' }), 3000);
    }, []);


    // --- Firestore Paths and Profile Management ---

    const getPublicCollectionRef = (collectionName) => collection(db, 'artifacts', appId, 'public', 'data', collectionName);
    const getUserProfileDoc = (uid) => doc(getPublicCollectionRef('userProfiles'), uid);
    const getChatDoc = (chatId) => doc(getPublicCollectionRef('chats'), chatId);
    const getMessagesCollectionRef = (chatId) => collection(getChatDoc(chatId), 'messages');

    // 1. Create User Profile, Fetch all Users, and Set Initial Display Name State
    useEffect(() => {
        // Only proceed if authenticated and ready (and user is not null)
        if (!isAuthReady || !db || !userId) {
            if (isAuthReady) setLoading(false);
            return;
        }

        const setupUserAndFetchUsers = async () => {
            setLoading(true);
            const profileRef = getUserProfileDoc(userId);
            const profileSnap = await getDoc(profileRef);
            
            // If profile does not exist, it means the user just registered via email/password 
            // but the profile write failed or is slow. This check is a fallback.
            if (!profileSnap.exists()) {
                console.log('Profile missing. Waiting for registration process to complete.');
                // We trust the registration process in AuthModal created the profile.
                // We wait for profile creation if it was a new registration.
            } else {
                const data = profileSnap.data();
                setNewDisplayName(data.displayName);
            }

            // Real-time listener for all user profiles
            const usersQuery = query(getPublicCollectionRef('userProfiles'));
            const unsubscribeUsers = onSnapshot(usersQuery, (snapshot) => {
                const userList = snapshot.docs.map(d => d.data());
                setUsers(userList);
                setLoading(false);
            }, (error) => {
                console.error("Error fetching users:", error);
                setLoading(false);
            });

            return () => unsubscribeUsers();
        };

        setupUserAndFetchUsers();
    }, [isAuthReady, db, userId]);

    // 2. Real-time Messages Listener for Active Chat
    useEffect(() => {
        if (!db || !activeChat) {
            setChatMessages([]);
            return;
        }

        const q = query(getMessagesCollectionRef(activeChat.id), orderBy('timestamp', 'asc'));

        const unsubscribeMessages = onSnapshot(q, (snapshot) => {
            const messages = snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
            setChatMessages(messages);
        }, (error) => {
            console.error("Error fetching messages:", error);
        });

        return () => unsubscribeMessages();
    }, [db, activeChat]);
    
    // --- Display Name Logic ---
    const handleSetDisplayName = useCallback(async (e) => {
        e.preventDefault();
        const minLength = 3;
        const trimmedName = newDisplayName.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');

        if (!db || !userId || trimmedName.length < minLength) {
            showSystemMessage(`Username must be at least ${minLength} characters long and contain only letters, numbers, or underscores.`, 'error');
            return;
        }

        // 1. Check if the name is already taken
        const usersRef = getPublicCollectionRef('userProfiles');
        const q = query(usersRef, where('displayName', '==', trimmedName));

        try {
            const querySnapshot = await getDocs(q);

            // Check if any document is found AND that document's ID is NOT the current user's ID
            const isTaken = querySnapshot.docs.some(doc => doc.id !== userId);

            if (isTaken) {
                showSystemMessage(`The username "${trimmedName}" is already taken. Try another one!`, 'error');
                return;
            }

            // 2. Update the user's profile
            const profileRef = getUserProfileDoc(userId);
            await updateDoc(profileRef, { displayName: trimmedName });

            showSystemMessage(`Username updated to "${trimmedName}"!`, 'success');
            setIsEditingDisplayName(false);
            setActiveChat(null); // Force reset to prevent stale partner name display
        } catch (error) {
            console.error("Error setting display name:", error);
            showSystemMessage('Failed to set username due to a network error.', 'error');
        }
    }, [db, userId, newDisplayName, showSystemMessage, setIsEditingDisplayName, getPublicCollectionRef, getUserProfileDoc]);

    // --- Auth Handlers ---
    const handleSignOut = useCallback(async () => {
        if (!auth) return;
        try {
            await signOut(auth);
            // After sign out, the onAuthStateChanged listener will fire and trigger the AuthModal
            showSystemMessage('Successfully signed out. Please sign in or register to continue.', 'success');
            setActiveChat(null);
            setUserId(null); // Explicitly clear state
            setUsers([]); // Clear user list until new auth state is ready
        } catch (error) {
            console.error("Sign out error:", error);
            showSystemMessage('Sign out failed.', 'error');
        }
    }, [auth, showSystemMessage]);

    const handleAuthSuccess = useCallback(() => {
        setIsAuthModalOpen(false);
        // The onAuthStateChanged listener handles state updates
    }, []);


    // --- Chat Logic ---
    const getChatId = (otherUserId) => {
        // Ensure canonical ID by sorting UIDs
        const participants = [userId, otherUserId].sort();
        return `${participants[0]}_${participants[1]}`;
    };

    const handleSelectUser = useCallback(async (otherUser) => {
        if (otherUser.uid === userId) return; // Cannot chat with self
        // Note: The main app logic now ensures userId is set before this is even callable.

        setLoading(true);
        const chatId = getChatId(otherUser.uid);
        const chatRef = getChatDoc(chatId);
        let chatData;
        let unsubscribeChat = () => {}; // Initialize empty unsubscribe function

        try {
            const chatSnap = await getDoc(chatRef);

            if (!chatSnap.exists()) {
                // Create new chat document if it doesn't exist
                chatData = {
                    participants: [userId, otherUser.uid],
                    type: 'DM',
                    callState: 'none', // 'none', 'requesting', 'active'
                };
                await setDoc(chatRef, chatData);
                showSystemMessage(`New chat started with ${otherUser.displayName}!`);
            } else {
                chatData = chatSnap.data();
            }

            // Real-time listener for the chat document itself (for call state updates)
            unsubscribeChat = onSnapshot(chatRef, (docSnap) => {
                if (docSnap.exists()) {
                    setActiveChat({ id: chatId, ...docSnap.data() });
                } else {
                    setActiveChat(null);
                }
            });

            setActiveChat({ id: chatId, ...chatData });
            setLoading(false);
            return unsubscribeChat;
        } catch (error) {
            console.error("Error selecting user/chat:", error);
            showSystemMessage('Failed to start chat.');
            setLoading(false);
            // Return a cleanup function regardless of success
            return unsubscribeChat; 
        }
    }, [db, userId, showSystemMessage, getChatDoc]);


    // Wrap the message send function in useCallback
    const handleSendMessage = useCallback(async (e) => {
        e.preventDefault();
        const messageText = messageInput.trim(); 

        if (!db || !activeChat || messageText === '') return;

        // Clear input immediately to maintain responsiveness
        setMessageInput(''); 

        try {
            await addDoc(getMessagesCollectionRef(activeChat.id), {
                senderId: userId,
                text: messageText,
                timestamp: serverTimestamp(),
            });
        } catch (error) {
            console.error("Error sending message:", error);
            showSystemMessage('Failed to send message.');
        }
    }, [db, activeChat, userId, messageInput, showSystemMessage, getMessagesCollectionRef]);

    // --- Call Simulation Logic ---
    const updateCallState = async (newState) => {
        if (!db || !activeChat) return;

        const chatRef = getChatDoc(activeChat.id);
        await updateDoc(chatRef, { callState: newState });

        const otherUser = activeChat.participants.find(id => id !== userId);
        const otherDisplayName = users.find(u => u.uid === otherUser)?.displayName || 'User';

        if (newState === 'requesting') {
            showSystemMessage(`Calling ${otherDisplayName}...`);
        } else if (newState === 'active') {
            showSystemMessage(`Call with ${otherDisplayName} started! (Mock)`);
        } else if (activeChat.callState === 'active' && newState === 'none') {
            showSystemMessage(`Call with ${otherDisplayName} ended.`);
        }
    };

    const handleCallAction = (action) => {
        if (!activeChat) return;

        switch (action) {
            case 'start':
                if (activeChat.callState === 'none') {
                    updateCallState('requesting');
                }
                break;
            case 'accept':
                if (activeChat.callState === 'requesting') {
                    updateCallState('active');
                }
                break;
            case 'end':
                updateCallState('none');
                break;
            default:
                break;
        }
    };


    // --- UI Render Helpers ---
    const getChatPartner = () => {
        if (!activeChat) return null;
        const partnerId = activeChat.participants.find(id => id !== userId);
        return users.find(u => u.uid === partnerId);
    };

    // --- Filtered Users for Search ---
    const filteredUsers = users.filter(user => {
        const query = searchQuery.toLowerCase();
        // Search by Display Name OR User ID
        const nameMatch = user.displayName.toLowerCase().includes(query);
        const idMatch = user.uid.toLowerCase().includes(query);
        return nameMatch || idMatch;
    });

    const ChatPanel = () => {
        const partner = getChatPartner();
        if (!partner) {
            return (
                <div className="flex-1 flex flex-col items-center justify-center p-6 bg-gray-700 text-gray-400">
                    <MessageSquare size={48} className="mb-4" />
                    <p className="text-xl font-semibold">Select a user to start a conversation.</p>
                </div>
            );
        }

        const isMyCall = activeChat.callState === 'requesting' && activeChat.participants.indexOf(userId) === 0;
        const isReceivingCall = activeChat.callState === 'requesting' && activeChat.participants.indexOf(userId) === 1;

        return (
            <div className="flex flex-col flex-1 bg-gray-700">
                {/* Chat Header */}
                <div className="p-4 bg-gray-800 flex items-center justify-between shadow-md">
                    <h2 className="text-white text-xl font-bold flex items-center">
                        <UserCheck className="mr-2 h-5 w-5 text-green-400" />
                        {partner.displayName}
                        <span className="text-sm font-mono ml-3 text-gray-400 opacity-75 hidden sm:inline">ID: {partner.uid}</span>
                    </h2>
                    
                    {/* Call Status & Controls */}
                    <div className="flex items-center space-x-3">
                        {activeChat.callState === 'none' && (
                            <button
                                onClick={() => handleCallAction('start')}
                                className="p-2 rounded-full bg-green-500 hover:bg-green-600 transition duration-150 text-white shadow-lg flex items-center"
                                title="Start Call"
                            >
                                <Phone size={20} />
                            </button>
                        )}

                        {isReceivingCall && (
                            <div className="flex items-center space-x-2 p-2 bg-yellow-600 rounded-full text-white shadow-md">
                                <span className="animate-pulse text-sm mr-1 hidden sm:inline">Incoming Call...</span>
                                <button
                                    onClick={() => handleCallAction('accept')}
                                    className="p-1 rounded-full bg-green-500 hover:bg-green-700 transition"
                                    title="Accept"
                                ><Mic size={18} /></button>
                                <button
                                    onClick={() => handleCallAction('end')}
                                    className="p-1 rounded-full bg-red-500 hover:bg-red-700 transition"
                                    title="Decline"
                                ><X size={18} /></button>
                            </div>
                        )}

                        {isMyCall && (
                             <div className="flex items-center space-x-2 p-2 bg-yellow-600 rounded-full text-white shadow-md">
                                <Loader size={20} className="animate-spin mr-1" />
                                <span className="text-sm mr-1 hidden sm:inline">Ringing...</span>
                                <button
                                    onClick={() => handleCallAction('end')}
                                    className="p-1 rounded-full bg-red-500 hover:bg-red-700 transition"
                                    title="Cancel"
                                ><X size={18} /></button>
                            </div>
                        )}

                        {activeChat.callState === 'active' && (
                            <div className="flex items-center space-x-3 p-2 bg-red-700 rounded-full text-white shadow-xl">
                                <span className="font-bold text-sm hidden sm:inline">Call Active (Mock)</span>
                                <button
                                    onClick={() => handleCallAction('end')}
                                    className="p-1 rounded-full bg-red-500 hover:bg-red-600 transition duration-150"
                                    title="End Call"
                                >
                                    <Phone size={20} className="rotate-12" />
                                </button>
                            </div>
                        )}
                    </div>
                </div>

                {/* Messages Area */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                    {chatMessages.length === 0 && (
                        <div className="text-center text-gray-500 pt-8">
                            Start chatting with {partner.displayName}!
                        </div>
                    )}
                    {chatMessages.map((msg) => {
                        const isMe = msg.senderId === userId;
                        const sender = isMe ? 'You' : partner.displayName;
                        return (
                            <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-xs lg:max-w-md p-3 rounded-xl shadow-md ${isMe ? 'bg-indigo-600 text-white' : 'bg-gray-600 text-gray-100'}`}>
                                    <div className="font-bold text-xs mb-1 opacity-80">
                                        {sender}
                                        <span className="ml-2 font-normal text-gray-300">
                                            {msg.timestamp ? new Date(msg.timestamp.seconds * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                                        </span>
                                    </div>
                                    <p className="whitespace-pre-wrap">{msg.text}</p>
                                </div>
                            </div>
                        );
                    })}
                    <div ref={messagesEndRef} />
                </div>

                {/* Message Input (Now a separate, memoized component) */}
                <MessageInput 
                    activeChat={activeChat}
                    messageInput={messageInput}
                    setMessageInput={setMessageInput}
                    handleSendMessage={handleSendMessage}
                    partnerDisplayName={partner.displayName}
                />
            </div>
        );
    };

    // --- Main Layout ---
    // If the auth process is running or the user data is loading, show a loading screen.
    if (loading && !isAuthReady) {
        return (
            <div className="h-screen flex items-center justify-center bg-gray-900 text-white">
                <Loader size={36} className="animate-spin mr-3" />
                Connecting to the Citadel...
            </div>
        );
    }
    
    const myProfile = users.find(u => u.uid === userId);

    return (
        // Added custom CSS for the background animation
        <div className="h-screen flex text-white font-inter relative overflow-hidden">
            <script src="https://cdn.tailwindcss.com"></script>
            <style>{`
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap');
                .font-inter { font-family: 'Inter', sans-serif; }

                /* Custom Plasma Animation */
                @keyframes bg-move {
                    0% {
                        background-position: 0% 0%;
                    }
                    50% {
                        background-position: 100% 100%;
                    }
                    100% {
                        background-position: 0% 0%;
                    }
                }

                .animated-bg {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(135deg, #1f1d36, #090333, #382455, #1f1d36);
                    background-size: 400% 400%;
                    animation: bg-move 25s ease infinite;
                    opacity: 0.8; /* Keep the content visible and legible */
                    z-index: 0;
                }
            `}</style>
            
            {/* Animated Background Layer */}
            <div className="animated-bg"></div>

            {/* Content Container (z-10 to layer above background) */}
            <div className="flex flex-1 z-10">
                {/* System Message Overlay */}
                {systemMessage.visible && (
                    <div className={`fixed top-4 right-4 z-50 p-4 rounded-lg shadow-xl transition-opacity duration-300 ease-out animate-in fade-in slide-in-from-right 
                        ${systemMessage.type === 'error' ? 'bg-red-600' : 'bg-green-500'} text-white`}>
                        <p>{systemMessage.text}</p>
                    </div>
                )}
                
                {/* Modals */}
                <DisplayNameModal 
                    isEditingDisplayName={isEditingDisplayName}
                    newDisplayName={newDisplayName}
                    setNewDisplayName={setNewDisplayName}
                    handleSetDisplayName={handleSetDisplayName}
                    setIsEditingDisplayName={setIsEditingDisplayName}
                />

                {/* AuthModal will now open automatically if no user is signed in */}
                <AuthModal 
                    isOpen={isAuthModalOpen}
                    auth={auth}
                    db={db}
                    onAuthSuccess={handleAuthSuccess}
                    showSystemMessage={showSystemMessage}
                    getUserProfileDoc={getUserProfileDoc}
                    appId={appId} // Pass appId for synthetic email generation
                />

                {/* Left Sidebar (User/Friend List) */}
                <div className="w-64 bg-gray-800 bg-opacity-95 flex flex-col shadow-2xl relative">
                    {/* Header/Search */}
                    <div className="p-4 border-b border-gray-700 bg-gray-900 bg-opacity-95">
                        <h1 className="text-xl font-extrabold text-indigo-400 flex items-center mb-3">
                            <Zap className="mr-2" /> Dihcord Messaging
                        </h1>
                        <div className="relative">
                            <input
                                type="text"
                                placeholder="Search Name or UID..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full p-2 pl-10 text-sm bg-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                disabled={!userId}
                            />
                            <Search size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                        </div>
                    </div>

                    {/* Users List */}
                    <div className="flex-1 overflow-y-auto p-3 space-y-1">
                        <div className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center">
                            <Users size={16} className="mr-2" /> Direct Messages ({filteredUsers.length})
                        </div>
                        {filteredUsers.map(user => (
                            <button
                                key={user.uid}
                                onClick={() => handleSelectUser(user)}
                                disabled={user.uid === userId || !userId}
                                className={`w-full text-left p-2 rounded-lg transition duration-150 flex items-center hover:bg-gray-700 ${activeChat && activeChat.participants.includes(user.uid) ? 'bg-indigo-600 hover:bg-indigo-700 text-white' : 'text-gray-200'} ${!userId ? 'opacity-50 cursor-not-allowed' : ''}`}
                            >
                                <span className={`h-2 w-2 rounded-full mr-3 ${user.uid === userId ? 'bg-yellow-400' : 'bg-green-500'}`}></span>
                                <div className="flex-1 truncate">
                                    <span className="font-semibold">{user.displayName}</span>
                                    <span className="text-xs ml-2 text-gray-400">{user.uid === userId ? '(You)' : ''}</span>
                                    <p className="text-xs font-mono text-gray-400 overflow-hidden whitespace-nowrap text-ellipsis">
                                        {user.uid}
                                    </p>
                                </div>
                            </button>
                        ))}
                    </div>

                    {/* User Panel Footer with Auth Options */}
                    <div className="p-4 bg-gray-900 bg-opacity-95 border-t border-gray-700 flex flex-col space-y-2">
                        <div className="flex items-center justify-between">
                            <div className="truncate">
                                {/* Since anonymous is now mostly prevented, the color is green unless profile is loading */}
                                <p className={`font-bold text-sm text-green-300`}>{myProfile?.displayName || 'Loading...'}</p>
                                <p className="text-xs font-mono text-gray-400">UID: {userId || 'N/A'}</p>
                            </div>
                            <button
                                onClick={() => setIsEditingDisplayName(true)}
                                className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-300 transition"
                                title="Change Username"
                                disabled={!userId}
                            >
                                <Settings size={20} />
                            </button>
                        </div>

                        {/* Since user is guaranteed to be signed in (or blocked by modal), only sign-out is necessary here */}
                        <div className="flex justify-between space-x-2 pt-2 border-t border-gray-700">
                            {userId ? (
                                <button
                                    onClick={handleSignOut}
                                    className="w-full flex items-center justify-center px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition text-sm font-semibold"
                                    title="Sign Out"
                                >
                                    <LogOut size={16} className="mr-1" /> Sign Out
                                </button>
                            ) : (
                                // Show the Auth button if for some reason the modal hasn't caught it yet
                                <button
                                    onClick={() => setIsAuthModalOpen(true)}
                                    className="flex-1 flex items-center justify-center px-2 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition text-sm font-semibold"
                                    title="Login/Register"
                                >
                                    <LogIn size={16} className="mr-1" /> Login / Sign Up
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                {/* Main Content Area (Chat) */}
                <ChatPanel />
            </div>
        </div>
    );
};

export default App;
