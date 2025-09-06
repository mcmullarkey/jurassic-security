import { useState, useEffect } from 'react';
import apiService from './services/api';

interface CompletionScreenProps {
  securityLevel: number;
}

function CompletionScreen({}: CompletionScreenProps) {
  const [secretCode, setSecretCode] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchCompletionData = async () => {
      try {
        const data = await apiService.getCompletionData();
        setSecretCode(data.secretCode);
      } catch (err) {
        console.error('Failed to fetch completion data:', err);
        setSecretCode('Error loading code');
      } finally {
        setLoading(false);
      }
    };

    fetchCompletionData();
  }, []);
  
  return (
    <div className="flex flex-col items-center justify-center min-h-screen text-center p-4 sm:p-8 max-w-sm sm:max-w-md mx-auto">
      <p className="text-lg sm:text-xl text-green-400 mb-6 font-semibold">
        You've achieved Top Secret!
      </p>
      
      <div className="bg-gray-800 border border-green-500 rounded-lg p-4 sm:p-6 mb-6 w-full">
        <h2 className="text-base sm:text-lg font-bold text-green-400 mb-3">
          🦕 SECRET CODE 🦖
        </h2>
        <div className="bg-black rounded p-3 sm:p-4 font-mono text-green-300 text-lg sm:text-xl tracking-wider border">
          {loading ? 'Loading...' : secretCode}
        </div>
        <p className="text-sm text-gray-300 mt-3">
          Show this screen to Michael for your prize!
        </p>
      </div>
      
      <p className="text-gray-300 text-xs sm:text-sm px-2">
        Welcome to Jurassic Park's elite security team. 
        Life finds a way... and so did you! 🦴
      </p>
    </div>
  );
}

export default CompletionScreen;