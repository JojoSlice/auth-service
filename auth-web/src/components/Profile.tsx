import { useAuth } from '../auth';
import './Profile.css';

export function Profile() {
  const { user, logout, isLoading } = useAuth();

  if (!user) return null;

  return (
    <div className="profile-container">
      <div className="profile-card">
        {user.profile_picture_url && (
          <img
            src={user.profile_picture_url}
            alt=""
            className="profile-avatar"
          />
        )}
        <div className="profile-info">
          <h2 className="profile-name">{user.display_name || 'User'}</h2>
          <p className="profile-email">{user.email}</p>
        </div>
        <button
          className="profile-logout"
          onClick={logout}
          disabled={isLoading}
        >
          Sign Out
        </button>
      </div>
    </div>
  );
}
