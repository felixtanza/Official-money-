import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';

// Context for global state management
const AppContext = createContext();

// Hook to use the app context
const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within AppProvider');
  }
  return context;
};

// Notification Component
const Notification = ({ notification, onClose }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose();
    }, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`notification ${notification.type}`}>
      <div className="notification-content">
        <h4>{notification.title}</h4>
        <p>{notification.message}</p>
      </div>
      <button className="notification-close" onClick={onClose}>×</button>
    </div>
  );
};

// Auth Components
const AuthPage = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    full_name: '',
    phone: '',
    referral_code: ''
  });
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        showNotification({
          title: 'Success!',
          message: data.message,
          type: 'success'
        });
        onLogin(data.user);
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Authentication failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card animated-card">
        <div className="auth-header">
          <h1>EarnPlatform</h1>
          <p>Start earning money with simple tasks</p>
        </div>

        <div className="auth-tabs">
          <button 
            className={`tab ${isLogin ? 'active' : ''}`}
            onClick={() => setIsLogin(true)}
          >
            Login
          </button>
          <button 
            className={`tab ${!isLogin ? 'active' : ''}`}
            onClick={() => setIsLogin(false)}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {!isLogin && (
            <>
              <div className="form-group">
                <input
                  type="text"
                  placeholder="Full Name"
                  value={formData.full_name}
                  onChange={(e) => setFormData({...formData, full_name: e.target.value})}
                  required
                  className="form-input"
                />
              </div>
              <div className="form-group">
                <input
                  type="tel"
                  placeholder="Phone Number (254XXXXXXXXX)"
                  value={formData.phone}
                  onChange={(e) => setFormData({...formData, phone: e.target.value})}
                  required
                  className="form-input"
                />
              </div>
              <div className="form-group">
                <input
                  type="text"
                  placeholder="Referral Code (Optional)"
                  value={formData.referral_code}
                  onChange={(e) => setFormData({...formData, referral_code: e.target.value})}
                  className="form-input"
                />
              </div>
            </>
          )}
          
          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={formData.email}
              onChange={(e) => setFormData({...formData, email: e.target.value})}
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              required
              className="form-input"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
          </button>
        </form>

        {!isLogin && (
          <div className="auth-info">
            <p className="activation-notice">
              💡 New users need to deposit KSH 500 to activate their account and start earning!
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

// Dashboard Components
const WalletCard = ({ user, onDeposit, onWithdraw }) => {
  return (
    <div className="wallet-card animated-card">
      <div className="wallet-header">
        <h3>💰 My Wallet</h3>
        <div className={`activation-status ${user.is_activated ? 'active' : 'inactive'}`}>
          {user.is_activated ? '✅ Activated' : '⏳ Pending Activation'}
        </div>
      </div>
      
      <div className="wallet-balance">
        <span className="currency">KSH</span>
        <span className="amount">{user.wallet_balance.toFixed(2)}</span>
      </div>

      {!user.is_activated && (
        <div className="activation-notice">
          <p>Deposit KSH {user.activation_amount} to activate your account and start earning!</p>
        </div>
      )}

      <div className="wallet-actions">
        <button className="btn-deposit" onClick={onDeposit}>
          💳 Deposit
        </button>
        <button 
          className="btn-withdraw" 
          onClick={onWithdraw}
          disabled={!user.is_activated || user.wallet_balance < 100}
        >
          💸 Withdraw
        </button>
      </div>

      <div className="wallet-stats">
        <div className="stat">
          <span className="stat-label">Total Earned</span>
          <span className="stat-value">KSH {user.total_earned.toFixed(2)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Total Withdrawn</span>
          <span className="stat-value">KSH {user.total_withdrawn.toFixed(2)}</span>
        </div>
      </div>
    </div>
  );
};

const TaskCard = ({ task, onComplete, completed = false }) => {
  const getTaskIcon = (type) => {
    switch (type) {
      case 'survey': return '📋';
      case 'ad': return '📺';
      case 'writing': return '✍️';
      case 'social': return '📱';
      default: return '⭐';
    }
  };

  return (
    <div className={`task-card animated-card ${completed ? 'completed' : ''}`}>
      <div className="task-header">
        <span className="task-icon">{getTaskIcon(task.type)}</span>
        <span className="task-reward">+KSH {task.reward}</span>
      </div>
      
      <h4 className="task-title">{task.title}</h4>
      <p className="task-description">{task.description}</p>
      
      <div className="task-footer">
        <span className="task-type">{task.type.toUpperCase()}</span>
        {!completed && (
          <button className="btn-task" onClick={() => onComplete(task)}>
            Complete
          </button>
        )}
      </div>
    </div>
  );
};

const ReferralCard = ({ user, stats }) => {
  const referralLink = `${window.location.origin}?ref=${user.referral_code}`;
  const { showNotification } = useAppContext();

  const copyReferralLink = () => {
    navigator.clipboard.writeText(referralLink);
    showNotification({
      title: 'Copied!',
      message: 'Referral link copied to clipboard',
      type: 'success'
    });
  };

  return (
    <div className="referral-card animated-card">
      <div className="referral-header">
        <h3>👥 Referral Program</h3>
        <div className="referral-reward">KSH 50 per referral</div>
      </div>

      <div className="referral-stats">
        <div className="stat">
          <span className="stat-value">{user.referral_count}</span>
          <span className="stat-label">Total Referrals</span>
        </div>
        <div className="stat">
          <span className="stat-value">KSH {user.referral_earnings.toFixed(2)}</span>
          <span className="stat-label">Referral Earnings</span>
        </div>
      </div>

      <div className="referral-link-section">
        <label>Your Referral Code:</label>
        <div className="referral-code-container">
          <input type="text" value={user.referral_code} readOnly className="referral-code" />
          <button className="btn-copy" onClick={copyReferralLink}>Copy Link</button>
        </div>
      </div>

      <div className="referral-encouragement">
        <p>🚀 Share your referral link and earn KSH 50 for each friend who joins and activates their account!</p>
        <p>💡 The more you refer, the more you earn!</p>
      </div>
    </div>
  );
};

const StatsCard = ({ title, value, icon, color }) => {
  return (
    <div className={`stats-card animated-card ${color}`}>
      <div className="stats-icon">{icon}</div>
      <div className="stats-content">
        <h4>{title}</h4>
        <div className="stats-value">{value}</div>
      </div>
    </div>
  );
};

// Modal Components
const DepositModal = ({ isOpen, onClose, onDeposit }) => {
  const [amount, setAmount] = useState('500');
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  const handleDeposit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/payments/deposit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          phone: phone
        }),
      });

      const data = await response.json();

      if (data.success) {
        showNotification({
          title: 'Deposit Initiated!',
          message: data.message,
          type: 'success'
        });
        // No longer simulating success here. Backend callback will handle actual update.
        onClose(); // Close modal immediately
        onDeposit(); // Trigger dashboard refresh for potential immediate visual update (though actual balance update is async via callback)
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Deposit failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>💳 Deposit Money</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        
        <form onSubmit={handleDeposit}>
          <div className="form-group">
            <label>Amount (KSH)</label>
            <input
              type="number"
              min="1"
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <label>M-Pesa Phone Number</label>
            <input
              type="tel"
              placeholder="254XXXXXXXXX"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              required
              className="form-input"
            />
          </div>

          <div className="deposit-info">
            <p>📱 You will receive an M-Pesa prompt on your phone</p>
            <p>⏱️ Complete the payment within 5 minutes</p>
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : 'Initiate Deposit'}
          </button>
        </form>
      </div>
    </div>
  );
};

const WithdrawModal = ({ isOpen, onClose, user, onWithdraw }) => {
  const [amount, setAmount] = useState('');
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  const handleWithdraw = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/payments/withdraw`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          phone: phone
        }),
      });

      const data = await response.json();

      if (data.success) {
        showNotification({
          title: 'Withdrawal Requested!',
          message: data.message,
          type: 'success'
        });
        onWithdraw();
        onClose();
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Withdrawal failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>💸 Withdraw Money</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        
        <form onSubmit={handleWithdraw}>
          <div className="form-group">
            <label>Amount (KSH)</label>
            <input
              type="number"
              min="100"
              max={user.wallet_balance}
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              required
              className="form-input"
            />
            <small>Available: KSH {user.wallet_balance.toFixed(2)} | Minimum: KSH 100</small>
          </div>
          
          <div className="form-group">
            <label>M-Pesa Phone Number</label>
            <input
              type="tel"
              placeholder="254XXXXXXXXX"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              required
              className="form-input"
            />
          </div>

          <div className="withdraw-info">
            <p>⏳ Processing time: 24-48 hours</p>
            <p>💰 Money will be sent to your M-Pesa account</p>
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : 'Request Withdrawal'}
          </button>
        </form>
      </div>
    </div>
  );
};

// Main Dashboard Component (for regular users)
const Dashboard = ({ user, onLogout }) => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [dashboardData, setDashboardData] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const { theme, toggleTheme, showNotification } = useAppContext();

  useEffect(() => {
    fetchDashboardData();
    fetchTasks();
  }, [user.is_activated]); // Re-fetch if activation status changes

  const fetchDashboardData = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/dashboard/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();
      if (data.success) {
        setDashboardData(data);
        // Update user data in localStorage to reflect latest balance/activation status
        localStorage.setItem('user', JSON.stringify(data.user));
      }
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      showNotification({
        title: 'Error',
        message: 'Failed to load dashboard data. Please refresh.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchTasks = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks/available`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();
      if (data.success) {
        setTasks(data.tasks);
      } else {
        // Handle cases where tasks might not be available due to non-activation
        if (data.detail === "Account must be activated to access tasks") {
          setTasks([]); // Clear tasks if not activated
        }
      }
    } catch (error) {
      console.error('Error fetching tasks:', error);
    }
  };

  const completeTask = async (task) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          task_id: task.task_id,
          completion_data: { completed_at: new Date().toISOString() }
        }),
      });

      const data = await response.json();
      if (data.success) {
        showNotification({
          title: 'Task Completed!',
          message: data.message,
          type: 'success'
        });
        fetchDashboardData();
        fetchTasks();
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Task completion failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    }
  };

  const handleDeposit = () => {
    fetchDashboardData();
    setShowDepositModal(false);
  };

  const handleWithdraw = () => {
    fetchDashboardData();
    setShowWithdrawModal(false);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading your dashboard...</p>
      </div>
    );
  }

  return (
    <div className={`dashboard ${theme}`}>
      <header className="dashboard-header">
        <div className="header-content">
          <h1>EarnPlatform</h1>
          <div className="header-actions">
            <button className="theme-toggle" onClick={toggleTheme}>
              {theme === 'light' ? '🌙' : '☀️'}
            </button>
            <button className="btn-logout" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>
        
        <nav className="dashboard-nav">
          <button 
            className={`nav-item ${currentPage === 'dashboard' ? 'active' : ''}`}
            onClick={() => setCurrentPage('dashboard')}
          >
            📊 Dashboard
          </button>
          <button 
            className={`nav-item ${currentPage === 'tasks' ? 'active' : ''}`}
            onClick={() => setCurrentPage('tasks')}
          >
            ⭐ Tasks
          </button>
          <button 
            className={`nav-item ${currentPage === 'referrals' ? 'active' : ''}`}
            onClick={() => setCurrentPage('referrals')}
          >
            👥 Referrals
          </button>
        </nav>
      </header>

      <main className="dashboard-main">
        {currentPage === 'dashboard' && dashboardData && (
          <div className="dashboard-content">
            <div className="welcome-section">
              <h2>Welcome back, {dashboardData.user.full_name}! 👋</h2>
              <p>Ready to earn more money today?</p>
            </div>

            <div className="stats-grid">
              <StatsCard 
                title="Wallet Balance" 
                value={`KSH ${dashboardData.user.wallet_balance.toFixed(2)}`} 
                icon="💰" 
                color="green" 
              />
              <StatsCard 
                title="Total Earned" 
                value={`KSH ${dashboardData.user.total_earned.toFixed(2)}`} 
                icon="📈" 
                color="blue" 
              />
              <StatsCard 
                title="Referrals" 
                value={dashboardData.user.referral_count} 
                icon="👥" 
                color="purple" 
              />
              <StatsCard 
                title="Tasks Completed" 
                value={dashboardData.task_completions} 
                icon="✅" 
                color="orange" 
              />
            </div>

            <div className="dashboard-grid">
              <WalletCard 
                user={dashboardData.user}
                onDeposit={() => setShowDepositModal(true)}
                onWithdraw={() => setShowWithdrawModal(true)}
              />
              
              <ReferralCard 
                user={dashboardData.user}
                stats={dashboardData.referral_stats}
              />
            </div>

            {!dashboardData.user.is_activated && (
              <div className="activation-banner animated-card">
                <h3>🚀 Activate Your Account</h3>
                <p>Deposit KSH 500 to unlock all features and start earning money through tasks!</p>
                <button className="btn-primary" onClick={() => setShowDepositModal(true)}>
                  Activate Now
                </button>
              </div>
            )}
          </div>
        )}

        {currentPage === 'tasks' && (
          <div className="tasks-content">
            <div className="tasks-header">
              <h2>Available Tasks</h2>
              <p>Complete tasks to earn money and increase your wallet balance!</p>
            </div>

            {!user.is_activated ? (
              <div className="activation-required animated-card">
                <h3>Account Activation Required</h3>
                <p>Please activate your account by depositing KSH 500 to access tasks.</p>
                <button className="btn-primary" onClick={() => setShowDepositModal(true)}>
                  Activate Account
                </button>
              </div>
            ) : (
              <div className="tasks-grid">
                {tasks.map(task => (
                  <TaskCard 
                    key={task.task_id} 
                    task={task} 
                    onComplete={completeTask}
                  />
                ))}
                {tasks.length === 0 && (
                  <div className="no-tasks">
                    <h3>🎉 All Tasks Completed!</h3>
                    <p>Great job! Check back later for new tasks.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {currentPage === 'referrals' && dashboardData && (
          <div className="referrals-content">
            <ReferralCard 
              user={dashboardData.user}
              stats={dashboardData.referral_stats}
            />
            
            <div className="referral-tips animated-card">
              <h3>💡 Referral Tips</h3>
              <ul>
                <li>Share your referral link on social media platforms</li>
                <li>Tell friends and family about the earning opportunities</li>
                <li>Earn KSH 50 for each successful referral who activates their account</li>
                <li>The more you refer, the more passive income you generate!</li>
              </ul>
            </div>
          </div>
        )}
      </main>

      <DepositModal 
        isOpen={showDepositModal}
        onClose={() => setShowDepositModal(false)}
        onDeposit={handleDeposit}
      />

      <WithdrawModal 
        isOpen={showWithdrawModal}
        onClose={() => setShowWithdrawModal(false)}
        user={dashboardData?.user || user}
        onWithdraw={handleWithdraw}
      />
    </div>
  );
};

// --- Admin Components ---

// Admin Dashboard Main Component
const AdminDashboard = ({ user, onLogout }) => {
  const [currentPage, setCurrentPage] = useState('admin-stats');
  const { theme, toggleTheme, showNotification } = useAppContext();

  return (
    <div className={`dashboard ${theme}`}>
      <header className="dashboard-header">
        <div className="header-content">
          <h1>EarnPlatform Admin</h1>
          <div className="header-actions">
            <button className="theme-toggle" onClick={toggleTheme}>
              {theme === 'light' ? '🌙' : '☀️'}
            </button>
            <button className="btn-logout" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>
        
        <nav className="dashboard-nav">
          <button 
            className={`nav-item ${currentPage === 'admin-stats' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-stats')}
          >
            📊 Overview
          </button>
          <button 
            className={`nav-item ${currentPage === 'admin-users' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-users')}
          >
            👥 Users
          </button>
          <button 
            className={`nav-item ${currentPage === 'admin-deposits' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-deposits')}
          >
            💳 Deposits
          </button>
          <button 
            className={`nav-item ${currentPage === 'admin-withdrawals' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-withdrawals')}
          >
            💸 Withdrawals
          </button>
          <button 
            className={`nav-item ${currentPage === 'admin-tasks' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-tasks')}
          >
            ⭐ Tasks
          </button>
          <button 
            className={`nav-item ${currentPage === 'admin-notifications' ? 'active' : ''}`}
            onClick={() => setCurrentPage('admin-notifications')}
          >
            🔔 Notifications
          </button>
        </nav>
      </header>

      <main className="dashboard-main">
        {currentPage === 'admin-stats' && <AdminStatsComponent />}
        {currentPage === 'admin-users' && <AdminUsersComponent />}
        {currentPage === 'admin-deposits' && <AdminDepositsComponent />}
        {currentPage === 'admin-withdrawals' && <AdminWithdrawalsComponent />}
        {currentPage === 'admin-tasks' && <AdminTasksComponent />}
        {currentPage === 'admin-notifications' && <AdminNotificationsComponent />}
      </main>
    </div>
  );
};

// Admin Stats Component
const AdminStatsComponent = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const { showNotification } = useAppContext();

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/dashboard/stats`, {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await response.json();
        if (data.success) {
          setStats(data.stats);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch admin stats', type: 'error' });
        }
      } catch (error) {
        showNotification({ title: 'Error', message: 'Network error fetching admin stats.', type: 'error' });
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading admin stats...</p></div>;
  if (!stats) return <div className="error-message">Failed to load admin stats.</div>;

  return (
    <div className="admin-content">
      <h2>Admin Overview</h2>
      <div className="stats-grid">
        <StatsCard title="Total Users" value={stats.total_users} icon="👥" color="blue" />
        <StatsCard title="Activated Users" value={stats.activated_users} icon="✅" color="green" />
        <StatsCard title="Total Deposits" value={`KSH ${stats.total_deposits.toFixed(2)}`} icon="💰" color="purple" />
        <StatsCard title="Total Withdrawals" value={`KSH ${stats.total_withdrawals.toFixed(2)}`} icon="💸" color="orange" />
        <StatsCard title="Pending Withdrawals" value={stats.pending_withdrawals} icon="⏳" color="red" />
      </div>
    </div>
  );
};

// Admin Users Component
const AdminUsersComponent = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const { showNotification } = useAppContext();

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/users`, {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await response.json();
        if (data.success) {
          setUsers(data.users);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch users', type: 'error' });
        }
      } catch (error) {
        showNotification({ title: 'Error', message: 'Network error fetching users.', type: 'error' });
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, []);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading users...</p></div>;

  return (
    <div className="admin-content">
      <h2>All Users</h2>
      <div className="table-container animated-card">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Phone</th>
              <th>Balance</th>
              <th>Activated</th>
              <th>Role</th>
              <th>Referrals</th>
              <th>Joined At</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.user_id}>
                <td>{user.full_name}</td>
                <td>{user.email}</td>
                <td>{user.phone}</td>
                <td>KSH {user.wallet_balance.toFixed(2)}</td>
                <td>{user.is_activated ? 'Yes' : 'No'}</td>
                <td>{user.role}</td>
                <td>{user.referral_count}</td>
                <td>{new Date(user.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
            {users.length === 0 && <tr><td colSpan="8">No users found.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Admin Deposits Component
const AdminDepositsComponent = () => {
  const [deposits, setDeposits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('');
  const { showNotification } = useAppContext();

  const fetchDeposits = async (status = '') => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const url = status ? `${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions/deposits?status=${status}` : `${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions/deposits`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (data.success) {
        setDeposits(data.deposits);
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to fetch deposits', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error fetching deposits.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDeposits(filterStatus);
  }, [filterStatus]);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading deposits...</p></div>;

  return (
    <div className="admin-content">
      <h2>All Deposits</h2>
      <div className="filter-controls">
        <label>Filter by Status:</label>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="form-select">
          <option value="">All</option>
          <option value="pending">Pending</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
      </div>
      <div className="table-container animated-card">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>User Email</th>
              <th>Amount</th>
              <th>Phone</th>
              <th>Status</th>
              <th>Receipt</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {deposits.map(deposit => (
              <tr key={deposit.transaction_id}>
                <td>{deposit.transaction_id.substring(0, 8)}...</td>
                <td>{deposit.user_id.substring(0, 8)}...</td> {/* In a real app, fetch user email */}
                <td>KSH {deposit.amount.toFixed(2)}</td>
                <td>{deposit.phone}</td>
                <td>{deposit.status}</td>
                <td>{deposit.mpesa_receipt || 'N/A'}</td>
                <td>{new Date(deposit.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {deposits.length === 0 && <tr><td colSpan="7">No deposits found.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Admin Withdrawals Component
const AdminWithdrawalsComponent = () => {
  const [withdrawals, setWithdrawals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('');
  const { showNotification } = useAppContext();

  const fetchWithdrawals = async (status = '') => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const url = status ? `${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions/withdrawals?status=${status}` : `${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions/withdrawals`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (data.success) {
        setWithdrawals(data.withdrawals);
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to fetch withdrawals', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error fetching withdrawals.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const updateWithdrawalStatus = async (transactionId, status, reason = null) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions/withdrawals/${transactionId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ status, reason }),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({ title: 'Success', message: data.message, type: 'success' });
        fetchWithdrawals(filterStatus); // Refresh list
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to update withdrawal status', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error updating withdrawal status.', type: 'error' });
    }
  };

  useEffect(() => {
    fetchWithdrawals(filterStatus);
  }, [filterStatus]);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading withdrawals...</p></div>;

  return (
    <div className="admin-content">
      <h2>All Withdrawals</h2>
      <div className="filter-controls">
        <label>Filter by Status:</label>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="form-select">
          <option value="">All</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="processing">Processing (M-Pesa B2C)</option>
          <option value="completed">Completed</option>
          <option value="rejected">Rejected</option>
          <option value="failed">Failed</option>
          <option value="timed_out">Timed Out</option>
        </select>
      </div>
      <div className="table-container animated-card">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>User Email</th>
              <th>Amount</th>
              <th>Phone</th>
              <th>Status</th>
              <th>Requested At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {withdrawals.map(withdrawal => (
              <tr key={withdrawal.transaction_id}>
                <td>{withdrawal.transaction_id.substring(0, 8)}...</td>
                <td>{withdrawal.user_id.substring(0, 8)}...</td> {/* In a real app, fetch user email */}
                <td>KSH {withdrawal.amount.toFixed(2)}</td>
                <td>{withdrawal.phone}</td>
                <td>{withdrawal.status}</td>
                <td>{new Date(withdrawal.created_at).toLocaleString()}</td>
                <td>
                  {withdrawal.status === 'pending' && (
                    <>
                      <button 
                        className="btn-action btn-approve" 
                        onClick={() => updateWithdrawalStatus(withdrawal.transaction_id, 'approved')}
                      >
                        Approve
                      </button>
                      <button 
                        className="btn-action btn-reject" 
                        onClick={() => {
                          const reason = prompt("Reason for rejection:");
                          if (reason) updateWithdrawalStatus(withdrawal.transaction_id, 'rejected', reason);
                        }}
                      >
                        Reject
                      </button>
                    </>
                  )}
                  {(withdrawal.status === 'approved' || withdrawal.status === 'processing') &&
                     <span className="status-badge processing">Processing</span>
                  }
                  {withdrawal.status === 'completed' &&
                    <span className="status-badge completed">Completed</span>
                  }
                  {(withdrawal.status === 'rejected' || withdrawal.status === 'failed' || withdrawal.status === 'timed_out') &&
                    <span className="status-badge failed">Failed/Rejected</span>
                  }
                </td>
              </tr>
            ))}
            {withdrawals.length === 0 && <tr><td colSpan="7">No withdrawals found.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Admin Tasks Component
const CreateTaskModal = ({ isOpen, onClose, onCreate }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    reward: '',
    type: 'survey',
    requirements: '{}', // JSON string
    is_active: true
  });
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const payload = {
        ...formData,
        reward: parseFloat(formData.reward),
        requirements: JSON.parse(formData.requirements)
      };
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/tasks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({ title: 'Success', message: data.message, type: 'success' });
        onCreate();
        onClose();
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to create task', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error creating task. Ensure requirements is valid JSON.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>➕ Create New Task</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Title</label>
            <input type="text" name="title" value={formData.title} onChange={handleChange} required className="form-input" />
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea name="description" value={formData.description} onChange={handleChange} required className="form-input"></textarea>
          </div>
          <div className="form-group">
            <label>Reward (KSH)</label>
            <input type="number" name="reward" value={formData.reward} onChange={handleChange} min="1" step="0.01" required className="form-input" />
          </div>
          <div className="form-group">
            <label>Type</label>
            <select name="type" value={formData.type} onChange={handleChange} className="form-select">
              <option value="survey">Survey</option>
              <option value="ad">Advertisement</option>
              <option value="writing">Writing</option>
              <option value="social">Social Media</option>
              <option value="referral">Referral</option>
            </select>
          </div>
          <div className="form-group">
            <label>Requirements (JSON)</label>
            <textarea name="requirements" value={formData.requirements} onChange={handleChange} className="form-input" placeholder='e.g., {"questions": 10, "time_limit": 300}'></textarea>
            <small>Must be valid JSON string, e.g., {"min_words": 100}</small>
          </div>
          <div className="form-group checkbox-group">
            <input type="checkbox" name="is_active" checked={formData.is_active} onChange={handleChange} id="is_active_task" />
            <label htmlFor="is_active_task">Is Active</label>
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating...' : 'Create Task'}
          </button>
        </form>
      </div>
    </div>
  );
};
export default AdminTasksComponent;

const AdminTasksComponent = () => {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateTaskModal, setShowCreateTaskModal] = useState(false);
  const { showNotification } = useAppContext();

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/tasks`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (data.success) {
        setTasks(data.tasks);
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to fetch tasks', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error fetching tasks.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const toggleTaskStatus = async (taskId, currentStatus) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/tasks/${taskId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: !currentStatus }),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({ title: 'Success', message: data.message, type: 'success' });
        fetchTasks(); // Refresh list
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to update task status', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error updating task status.', type: 'error' });
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading tasks...</p></div>;

  return (
    <div className="admin-content">
      <h2>Manage Tasks</h2>
      <button className="btn-primary" onClick={() => setShowCreateTaskModal(true)}>
        ➕ Create New Task
      </button>
      <div className="table-container animated-card">
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Description</th>
              <th>Reward</th>
              <th>Type</th>
              <th>Active</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map(task => (
              <tr key={task.task_id}>
                <td>{task.title}</td>
                <td>{task.description}</td>
                <td>KSH {task.reward.toFixed(2)}</td>
                <td>{task.type}</td>
                <td>
                  <input 
                    type="checkbox" 
                    checked={task.is_active} 
                    onChange={() => toggleTaskStatus(task.task_id, task.is_active)} 
                  />
                </td>
                <td>{new Date(task.created_at).toLocaleDateString()}</td>
                <td>
                  {/* Future: Edit Task button */}
                </td>
              </tr>
            ))}
            {tasks.length === 0 && <tr><td colSpan="7">No tasks found.</td></tr>}
          </tbody>
        </table>
      </div>
      <CreateTaskModal 
        isOpen={showCreateTaskModal}
        onClose={() => setShowCreateTaskModal(false)}
        onCreate={fetchTasks}
      />
    </div>
  );
};

// Admin Notifications Component
const BroadcastNotificationModal = ({ isOpen, onClose, onBroadcast }) => {
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/notifications/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ title, message }),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({ title: 'Success', message: data.message, type: 'success' });
        onBroadcast();
        onClose();
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to broadcast notification', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error broadcasting notification.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>📢 Broadcast Notification</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Title</label>
            <input type="text" value={title} onChange={(e) => setTitle(e.target.value)} required className="form-input" />
          </div>
          <div className="form-group">
            <label>Message</label>
            <textarea value={message} onChange={(e) => setMessage(e.target.value)} required className="form-input"></textarea>
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Sending...' : 'Send Broadcast'}
          </button>
        </form>
      </div>
    </div>
  );
};

const AdminNotificationsComponent = () => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showBroadcastModal, setShowBroadcastModal] = useState(false);
  const { showNotification } = useAppContext();

  const fetchNotifications = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      // Admin can fetch all notifications (user_id: null for broadcast, or specific user_id)
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/notifications`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (data.success) {
        setNotifications(data.notifications);
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to fetch notifications', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error fetching notifications.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const markNotificationAsRead = async (notificationId) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      fetchNotifications(); // Refresh list
    } catch (error) {
      showNotification({ title: 'Error', message: 'Failed to mark notification as read.', type: 'error' });
    }
  };

  useEffect(() => {
    fetchNotifications();
  }, []);

  if (loading) return <div className="loading-container"><div className="loading-spinner"></div><p>Loading notifications...</p></div>;

  return (
    <div className="admin-content">
      <h2>Manage Notifications</h2>
      <button className="btn-primary" onClick={() => setShowBroadcastModal(true)}>
        📢 Broadcast New Notification
      </button>
      <div className="table-container animated-card">
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Message</th>
              <th>Target User ID</th>
              <th>Read</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {notifications.map(notification => (
              <tr key={notification.notification_id}>
                <td>{notification.title}</td>
                <td>{notification.message}</td>
                <td>{notification.user_id ? notification.user_id.substring(0, 8) + '...' : 'All Users'}</td>
                <td>{notification.is_read ? 'Yes' : 'No'}</td>
                <td>{new Date(notification.created_at).toLocaleString()}</td>
                <td>
                  {!notification.is_read && (
                    <button 
                      className="btn-action btn-mark-read" 
                      onClick={() => markNotificationAsRead(notification.notification_id)}
                    >
                      Mark Read
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {notifications.length === 0 && <tr><td colSpan="6">No notifications found.</td></tr>}
          </tbody>
        </table>
      </div>
      <BroadcastNotificationModal 
        isOpen={showBroadcastModal}
        onClose={() => setShowBroadcastModal(false)}
        onBroadcast={fetchNotifications}
      />
    </div>
  );
};


// Main App Component
const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notifications, setNotifications] = useState([]);
  const [theme, setTheme] = useState('light');

  useEffect(() => {
    // Check for existing session
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    
    if (token && savedUser) {
      const parsedUser = JSON.parse(savedUser);
      setUser(parsedUser);
      setTheme(parsedUser.theme || 'light');
    }
    
    // Check for referral code in URL
    const urlParams = new URLSearchParams(window.location.search);
    const refCode = urlParams.get('ref');
    if (refCode) {
      localStorage.setItem('referral_code', refCode);
    }
    
    setLoading(false);
  }, []);

  const showNotification = (notification) => {
    const id = Date.now();
    setNotifications(prev => [...prev, { ...notification, id }]);
  };

  const removeNotification = (id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    
    // Save theme preference
    if (user) {
      const token = localStorage.getItem('token');
      fetch(`${process.env.REACT_APP_BACKEND_URL}/api/settings/theme?theme=${newTheme}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
    }
  };

  const handleLogin = (userData) => {
    setUser(userData);
    setTheme(userData.theme || 'light');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    showNotification({
      title: 'Logged Out',
      message: 'You have been successfully logged out.',
      type: 'info'
    });
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading EarnPlatform...</p>
      </div>
    );
  }

  return (
    <AppContext.Provider value={{ 
      showNotification, 
      theme, 
      toggleTheme 
    }}>
      <div className={`app ${theme}`}>
        {!user ? (
          <AuthPage onLogin={handleLogin} />
        ) : (
          user.role === 'admin' ? (
            <AdminDashboard user={user} onLogout={handleLogout} />
          ) : (
            <Dashboard user={user} onLogout={handleLogout} />
          )
        )}

        <div className="notification-container">
          {notifications.map(notification => (
            <Notification
              key={notification.id}
              notification={notification}
              onClose={() => removeNotification(notification.id)}
            />
          ))}
        </div>
      </div>
    </AppContext.Provider>
  );
};

export default App;
