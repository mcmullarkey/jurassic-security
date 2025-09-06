interface QuestionTextProps {
  text: string;
}

const QuestionText = ({ text }: QuestionTextProps) => {
  return <div className="bg-orange-500 text-white p-4 m-4 rounded-lg">
       {text}
    </div>
}

export default QuestionText;