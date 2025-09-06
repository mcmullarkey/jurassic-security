import { useState, useEffect } from 'react'
import './App.css'
import FancyButton from './FancyButton'
import QuestionText from './QuestionText'
import AnswerInput from './AnswerInput'
import StartScreen from './StartScreen'
import SecurityLevelBar from './SecurityLevelBar'
import CompletionScreen from './CompletionScreen'
import LoginScreen from './LoginScreen'
import apiService from './services/api'

interface Question {
  id: number;
  text: string;
  icon: string;
}

type QuizResult = 'correct' | 'incorrect' | null;

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [hasStarted, setHasStarted] = useState<boolean>(false);
  const [isCompleted, setIsCompleted] = useState<boolean>(false);
  const [userAnswer, setUserAnswer] = useState<string>('');
  const [result, setResult] = useState<QuizResult>(null);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState<number>(0);
  const [securityLevel, setSecurityLevel] = useState<number>(1);
  const [questions, setQuestions] = useState<Question[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  
  const currentQuestion = questions[currentQuestionIndex];

  // Check for existing auth on app start
  useEffect(() => {
    const checkExistingAuth = async () => {
      try {
        setLoading(true);
        const isAuthenticated = await apiService.checkAuth();
        if (isAuthenticated) {
          setIsLoggedIn(true);
          // Questions are already loaded from checkAuth
          const fetchedQuestions = await apiService.getQuestions();
          setQuestions(fetchedQuestions);
        }
      } catch (error) {
        // Not authenticated, which is fine
      } finally {
        setLoading(false);
      }
    };

    checkExistingAuth();
  }, []);

  const loadQuestions = async (): Promise<void> => {
    try {
      setLoading(true);
      const fetchedQuestions = await apiService.getQuestions();
      setQuestions(fetchedQuestions);
      setError('');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load questions';
      setError(errorMessage);
      // Only log out if we're sure it's an authentication issue
      if (err instanceof Error && err.message === 'Authentication expired') {
        console.log('Authentication expired, logging out...');
        setIsLoggedIn(false);
        setHasStarted(false);
      } else {
        console.log('Non-auth error loading questions:', errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (): Promise<void> => {
    setIsLoggedIn(true);
    // Add a small delay to ensure the login session is fully established
    setTimeout(async () => {
      await loadQuestions();
    }, 100);
  };
  
  const advanceToNextQuestion = (): void => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
      setUserAnswer('');
      setResult(null);
      return;
    }
    // Completed all questions
    setIsCompleted(true);
  };

  const handleCorrectAnswer = (): void => {
    setResult('correct');
    setSecurityLevel(securityLevel + 1);
    setTimeout(advanceToNextQuestion, 500);
  };

  const handleSubmit = async (): Promise<void> => {
    if (!currentQuestion) return;
    
    try {
      setLoading(true);
      const response = await apiService.submitAnswer(currentQuestion.id, userAnswer.trim());
      
      if (response.correct) {
        handleCorrectAnswer();
      } else {
        setResult('incorrect');
        setTimeout(() => setResult(null), 750);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to submit answer';
      setError(errorMessage);
      if (err instanceof Error && err.message === 'Authentication expired') {
        console.log('Authentication expired during answer submit, logging out...');
        setIsLoggedIn(false);
        setHasStarted(false);
      } else {
        console.log('Non-auth error submitting answer:', errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };
  
  const getButtonText = (): string => {
    if (loading) return 'Checking...';
    if (result === 'correct') return 'Correct! 🎉';
    if (result === 'incorrect') return 'Try again!';
    return 'Submit Answer';
  };
  
  if (!isLoggedIn) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  if (!hasStarted) {
    return <StartScreen onBegin={() => setHasStarted(true)} />;
  }

  if (isCompleted) {
    return <CompletionScreen securityLevel={securityLevel} />;
  }

  return <div className="flex flex-col items-center p-4 min-h-screen justify-center max-w-md mx-auto">
      <SecurityLevelBar level={securityLevel} maxLevel={questions.length + 1} />
      <i className={`fa-solid ${currentQuestion.icon} text-white p-4 m-4 text-2xl sm:text-3xl`}></i>
      <QuestionText text={currentQuestion.text}/>
      <AnswerInput value={userAnswer} onChange={setUserAnswer} />
      {error && <div className="text-red-400 text-sm mt-2">{error}</div>}
      <FancyButton onClick={handleSubmit} 
      text={getButtonText()} />
    </div>;
}

export default App
