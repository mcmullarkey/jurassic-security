import { useRef } from 'react';

interface AnswerInputProps {
  value: string;
  onChange: (value: string) => void;
}

function AnswerInput({ value, onChange }: AnswerInputProps) {
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

  return (
    <div className="flex flex-col items-center gap-2 p-4">
      <input
        ref={inputRef}
        type="text"
        placeholder="Enter your answer..."
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={handleFocus}
        className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );
}

export default AnswerInput;