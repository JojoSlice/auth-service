import { useAuth } from './auth';
import { Login, NeonLogo, Profile } from './components';
import './App.css';

function App() {
  const { isAuthenticated, isLoading } = useAuth();

  return (
    <div className="app">
      <NeonLogo />
      <main className="app-main">
        {isLoading ? (
          <div className="app-loading">
            <div className="app-spinner"></div>
          </div>
        ) : isAuthenticated ? (
          <Profile />
        ) : (
          <Login />
        )}
      </main>
    </div>
  );
}

export default App;
