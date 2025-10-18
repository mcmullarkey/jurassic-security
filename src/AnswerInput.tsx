import { useRef } from 'react';

interface AnswerInputProps {
  value: string;
  onChange: (value: string) => void;
  questionText?: string;
}

function AnswerInput({ value, onChange, questionText = '' }: AnswerInputProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFocus = (): void => {
    // Delay to allow keyboard to appear first
    setTimeout(() => {
      inputRef.current?.scrollIntoView({
        behavior: 'smooth',
        block: 'center'
      });
    }, 300);
  };

  // Determine input type and placeholder based on question
  const isNumericQuestion = questionText.toLowerCase().includes('code') ||
                           questionText.toLowerCase().includes('milliliters') ||
                           questionText.toLowerCase().includes('year');

  const getPlaceholder = (): string => {
    if (questionText.toLowerCase().includes('code')) {
      return 'Enter access code (numbers only)...';
    }
    if (questionText.toLowerCase().includes('milliliters')) {
      return 'Enter number...';
    }
    if (questionText.toLowerCase().includes('year')) {
      return 'Enter year (numbers only)...';
    }
    return 'Enter your answer...';
  };

  return (
    <div className="flex flex-col items-center gap-2 p-4 w-full">
      <input
        ref={inputRef}
        type="text"
        inputMode={isNumericQuestion ? 'numeric' : 'text'}
        placeholder={getPlaceholder()}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={handleFocus}
        className="w-full max-w-sm px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );
}

export default AnswerInput;