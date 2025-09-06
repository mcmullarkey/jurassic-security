interface StartScreenProps {
  onBegin: () => void;
}

function StartScreen({ onBegin }: StartScreenProps): React.JSX.Element {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen text-center p-4 sm:p-8 relative">
      {/* Background logo */}
      <div 
        className="absolute inset-0 bg-cover sm:bg-contain bg-center bg-no-repeat opacity-10"
        style={{
          backgroundImage: "url('/src/assets/jurassic-park-logo.jpg')"
        }}
      ></div>
      
      {/* Content overlay */}
      <div className="relative z-10 px-4 max-w-sm sm:max-w-md">
      <h1 className="text-2xl sm:text-4xl font-bold text-white mb-4">
        Security Clearance Test
      </h1>
      <p className="text-base sm:text-lg text-gray-300 mb-8">
        Get top-secret Jurassic Park security clearance
      </p>
      <button 
        onClick={onBegin}
        className="w-full sm:w-auto px-8 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 transition-colors text-lg sm:text-xl"
      >
        Begin
      </button>
      </div>
    </div>
  );
}

export default StartScreen;