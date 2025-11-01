// Chat Data for HIreVerse Chat Application
const chatData = {
  currentUser: {
    id: 'user_001',
    name: 'You',
    avatar: 'U',
    avatarColor: '#90caf9'
  },
  
  contacts: [
    {
      id: 'contact_001',
      name: '24MCA128 KRISHI SHAH',
      shortName: '2S',
      avatar: null,
      avatarColor: '#ffa726',
      lastMessage: 'You: ass4',
      lastMessageTime: '8/20',
      isOnline: true,
      isFavorite: true,
      hasNotification: false,
      notificationType: 'success'
    },
    {
      id: 'contact_002',
      name: '24MCA127 DHRUMIL TRIVEDI',
      shortName: '2T',
      avatar: null,
      avatarColor: '#42a5f5',
      lastMessage: 'Sent a file',
      lastMessageTime: '9/1',
      isOnline: false,
      isFavorite: false,
      hasNotification: true,
      notificationType: 'warning'
    },
    {
      id: 'contact_003',
      name: '24MCA156 KISHAN YADAV',
      shortName: 'KY',
      avatar: 'assets/profile.jpeg',
      avatarColor: '#66bb6a',
      lastMessage: '',
      lastMessageTime: '7/7',
      isOnline: true,
      isFavorite: false,
      hasNotification: false,
      notificationType: 'success'
    },
    {
      id: 'contact_004',
      name: '24MCA127 DHRUMIL TRIVEDI',
      shortName: '2',
      avatar: null,
      avatarColor: '#42a5f5',
      lastMessage: '24MCA156 KISHAN YADAV: 404 ni err...',
      lastMessageTime: '3/31',
      isOnline: false,
      isFavorite: false,
      hasNotification: false,
      notificationType: null
    }
  ],
  
  conversations: {
    'contact_001': [
      {
        id: 'msg_001',
        senderId: 'user_001',
        senderName: 'You',
        message: 'hy',
        timestamp: '2025-09-22T10:30:00Z',
        type: 'text',
        isRead: true
      },
      {
        id: 'msg_002',
        senderId: 'contact_001',
        senderName: '24MCA128 KRISHI SHAH',
        message: 'ass4',
        timestamp: '2025-09-22T10:32:00Z',
        type: 'text',
        isRead: true
      }
    ],
    'contact_002': [
      {
        id: 'msg_003',
        senderId: 'contact_002',
        senderName: '24MCA127 DHRUMIL TRIVEDI',
        message: 'document.pdf',
        timestamp: '2025-09-01T15:45:00Z',
        type: 'file',
        isRead: false
      }
    ],
    'contact_003': [],
    'contact_004': [
      {
        id: 'msg_004',
        senderId: 'contact_003',
        senderName: '24MCA156 KISHAN YADAV',
        message: '404 ni error solve thy gayi?',
        timestamp: '2025-03-31T14:20:00Z',
        type: 'text',
        isRead: true
      }
    ]
  },
  
  chatFilters: [
    { id: 'unread', label: 'Unread', active: false },
    { id: 'chats', label: 'Chats', active: true }
  ]
};

// Utility functions for chat data
const chatUtils = {
  // Get formatted time string
  getTimeString: function(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
      return 'Today';
    } else if (diffDays <= 7) {
      return `${diffDays}d ago`;
    } else {
      return date.toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' });
    }
  },
  
  // Get contact by ID
  getContact: function(contactId) {
    return chatData.contacts.find(contact => contact.id === contactId);
  },
  
  // Get conversation by contact ID
  getConversation: function(contactId) {
    return chatData.conversations[contactId] || [];
  },
  
  // Add new message to conversation
  addMessage: function(contactId, message) {
    if (!chatData.conversations[contactId]) {
      chatData.conversations[contactId] = [];
    }
    
    const newMessage = {
      id: 'msg_' + Date.now(),
      senderId: chatData.currentUser.id,
      senderName: chatData.currentUser.name,
      message: message.text || '',
      timestamp: new Date().toISOString(),
      type: message.type || 'text',
      isRead: true
    };
    
    if (message.fileName) {
      newMessage.fileName = message.fileName;
      newMessage.type = 'file';
    }
    
    chatData.conversations[contactId].push(newMessage);
    
    // Update last message in contact
    const contact = this.getContact(contactId);
    if (contact) {
      contact.lastMessage = message.type === 'file' ? `You: ${message.fileName}` : `You: ${message.text}`;
      contact.lastMessageTime = this.getTimeString(newMessage.timestamp);
    }
    
    return newMessage;
  },
  
  // Filter contacts based on active filters
  getFilteredContacts: function() {
    let filtered = [...chatData.contacts];
    
    const activeFilter = chatData.chatFilters.find(filter => filter.active);
    
    if (activeFilter) {
      switch (activeFilter.id) {
        case 'unread':
          filtered = filtered.filter(contact => contact.hasNotification);
          break;
        case 'chats':
          // Show all regular chats (default)
          break;
      }
    }
    
    return filtered;
  },
  
  // Search contacts by name
  searchContacts: function(searchTerm) {
    if (!searchTerm) return this.getFilteredContacts();
    
    const term = searchTerm.toLowerCase();
    return this.getFilteredContacts().filter(contact => 
      contact.name.toLowerCase().includes(term)
    );
  },
  
  // Toggle favorite status
  toggleFavorite: function(contactId) {
    const contact = this.getContact(contactId);
    if (contact) {
      contact.isFavorite = !contact.isFavorite;
    }
    return contact;
  },
  
  // Set active filter
  setActiveFilter: function(filterId) {
    chatData.chatFilters.forEach(filter => {
      filter.active = filter.id === filterId;
    });
  }
};

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { chatData, chatUtils };
}