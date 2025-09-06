import { useState } from 'react';
import apiService from './services/api';

interface LoginScreenProps {
  onLogin: () => void;
}

function LoginScreen({ onLogin }: LoginScreenProps): React.JSX.Element {
  const [password, setPassword] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  const handleSubmit = async (): Promise<void> => {
    setLoading(true);
    setError('');

    try {
      await apiService.login(password.trim());
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setPassword('');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent): void => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen text-center px-4 py-8 sm:p-8 relative">
      {/* Background logo */}
      <div 
        className="absolute inset-0 bg-cover sm:bg-contain bg-center bg-no-repeat opacity-10"
        style={{
          backgroundImage: "url('/src/assets/jurassic-park-logo.jpg')"
        }}
      ></div>
      
      {/* Content overlay */}
      <div className="relative z-10 w-full max-w-xs sm:max-w-sm md:max-w-md">
        <div className="mb-6 sm:mb-8">
          <i className="fa-solid fa-lock text-white text-3xl sm:text-5xl md:text-6xl mb-4"></i>
        </div>
        
        <h1 className="text-xl sm:text-2xl md:text-4xl font-bold text-white mb-3 sm:mb-4">
          Access Required
        </h1>
        
        <p className="text-sm sm:text-base md:text-lg text-gray-300 mb-6 sm:mb-8">
          Enter password to access the security clearance test
        </p>
        
        <div className="space-y-3 sm:space-y-4">
          <input 
            type="password" 
            placeholder="Enter password..." 
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyPress={handleKeyPress}
            className="w-full px-3 sm:px-4 py-2 sm:py-3 text-sm sm:text-base rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
          />
          
          {error && (
            <div className="bg-red-900/30 border border-red-600 rounded-lg p-2 sm:p-3">
              <p className="text-red-400 text-xs sm:text-sm font-medium">{error}</p>
            </div>
          )}
          
          <button 
            onClick={handleSubmit}
            disabled={loading}
            className={`w-full px-6 sm:px-8 py-2 sm:py-3 font-semibold rounded-lg transition-all duration-200 text-base sm:text-lg md:text-xl ${
              loading 
                ? 'bg-gray-600 text-gray-300 cursor-not-allowed scale-95' 
                : 'bg-green-600 text-white hover:bg-green-700 hover:scale-105 active:scale-95'
            }`}
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <i className="fa-solid fa-spinner fa-spin"></i>
                Authenticating...
              </span>
            ) : (
              'Access System'
            )}
          </button>
        </div>
        
        {/* Subtle hint for mobile users */}
        <p className="text-xs text-gray-500 mt-4 sm:hidden">
          Tap password field to enter credentials
        </p>
      </div>
    </div>
  );
}

export default LoginScreen;