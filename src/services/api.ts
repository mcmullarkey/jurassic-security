const API_BASE_URL = '/api';

interface LoginResponse {
  success: boolean;
  message: string;
}

interface Question {
  id: number;
  text: string;
  icon: string;
}

interface QuestionsResponse {
  questions: Question[];
}

interface AnswerResponse {
  correct: boolean;
  message: string;
}

interface CompletionResponse {
  secretCode: string;
  message: string;
}

class ApiService {
  private getHeaders() {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    return headers;
  }

  async login(password: string): Promise<LoginResponse> {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: this.getHeaders(),
      credentials: 'include', // Important: include cookies
      body: JSON.stringify({ password })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Login failed');
    }

    const data: LoginResponse = await response.json();
    return data;
  }

  async getQuestions(): Promise<Question[]> {
    const response = await fetch(`${API_BASE_URL}/questions`, {
      headers: this.getHeaders(),
      credentials: 'include'
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error('Authentication expired');
      }
      throw new Error('Failed to fetch questions');
    }

    const data: QuestionsResponse = await response.json();
    return data.questions;
  }

  async submitAnswer(questionId: number, answer: string): Promise<AnswerResponse> {
    const response = await fetch(`${API_BASE_URL}/questions/${questionId}/answer`, {
      method: 'POST',
      headers: this.getHeaders(),
      credentials: 'include',
      body: JSON.stringify({ answer })
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error('Authentication expired');
      }
      throw new Error('Failed to submit answer');
    }

    return response.json();
  }

  async getCompletionData(): Promise<CompletionResponse> {
    const response = await fetch(`${API_BASE_URL}/completion`, {
      headers: this.getHeaders(),
      credentials: 'include'
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error('Authentication expired');
      }
      throw new Error('Failed to fetch completion data');
    }

    return response.json();
  }


  // Check auth by trying to fetch questions (server will return 401 if not authenticated)
  async checkAuth(): Promise<boolean> {
    try {
      await this.getQuestions();
      return true;
    } catch (error) {
      return false;
    }
  }

  // No longer needed with httpOnly cookies
  init(): void {
    // Method kept for backwards compatibility but does nothing
  }
}

export default new ApiService();