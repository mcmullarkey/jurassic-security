import { useState, useEffect } from 'react'
import './App.css'
import FancyButton from './FancyButton'
import QuestionText from './QuestionText'
import AnswerInput from './AnswerInput'
import StartScreen from './StartScreen'
import SecurityLevelBar from './SecurityLevelBar'
import CompletionScreen from './CompletionScreen'
import apiService from './services/api'

interface Question {
  id: number;
  text: string;
  icon: string;
}

type QuizResult = 'correct' | 'incorrect' | null;

function App() {
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

  // Load questions on app start
  useEffect(() => {
    const loadQuestions = async () => {
      try {
        setLoading(true);
        const fetchedQuestions = await apiService.getQuestions();
        setQuestions(fetchedQuestions);
        setError('');
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to load questions';
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    loadQuestions();
  }, []);
  
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
