import { type ChangeEvent, type KeyboardEvent, useState } from 'react';

interface CodeInputProps {
  code: string;
  language: 'python' | 'javascript' | 'typescript' | 'go' | 'rust' | 'java';
  isLoading: boolean;
  onCodeChange: (code: string) => void;
  onLanguageChange: (lang: CodeInputProps['language']) => void;
  onSubmit: () => void;
}

const LANGUAGES = [
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'go', label: 'Go' },
  { value: 'rust', label: 'Rust' },
  { value: 'java', label: 'Java' },
] as const;

const SAMPLE_CODE: Record<string, { label: string; code: string; language: CodeInputProps['language'] }[]> = {
  python: [
    {
      label: 'SQL injection + secrets',
      language: 'python',
      code: `import sqlite3

API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "super_secret_pass"

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def process_data(items=[]):  # mutable default arg
    results = []
    for item in items:
        try:
            result = eval(item)  # dangerous eval
            results.append(result)
        except:  # bare except
            pass
    return results`,
    },
    {
      label: 'Deep nesting',
      language: 'python',
      code: `def complex_function(data, config, options):
    if data:
        for item in data:
            if item > 0:
                for sub in config:
                    if sub:
                        while True:
                            if options:
                                x = 1
                                y = 2
                                break
    # TODO: fix this
    # FIXME: too complex
    return None`,
    },
  ],
  javascript: [
    {
      label: 'XSS + var usage',
      language: 'javascript',
      code: `var API_KEY = "ak_live_1234567890abcdef";

function loadProfile(userId) {
  fetch('/api/users/' + userId)
    .then(function(res) { return res.json(); })
    .then(function(data) {
      // XSS vulnerability
      document.getElementById('profile').innerHTML =
        '<h1>' + data.name + '</h1><p>' + data.bio + '</p>';
      console.log('Profile loaded:', data);
    });
}`,
    },
  ],
  typescript: [
    {
      label: 'any types + null safety',
      language: 'typescript',
      code: `async function fetchUser(id: any): Promise<any> {
  const response = await fetch(\`/api/users/\${id}\`);
  const data: any = await response.json();
  return data;
}

function renderUsers(users: any[]): void {
  users.forEach((user: any) => {
    console.log(user.name.toUpperCase());
    document.getElementById('list')!.innerHTML +=
      \`<li>\${user.name}</li>\`;
  });
}`,
    },
  ],
  go: [
    {
      label: 'SQL injection',
      language: 'go',
      code: `package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, username string) (string, error) {
	// SQL injection
	query := fmt.Sprintf("SELECT name FROM users WHERE username = '%s'", username)
	var name string
	err := db.QueryRow(query).Scan(&name)
	if err != nil {
		panic(err) // TODO: handle properly
	}
	return name, nil
}`,
    },
  ],
  rust: [
    {
      label: 'Code smells',
      language: 'rust',
      code: `// TODO: add proper error types
fn process_data(input: &str) -> String {
    let mut results = Vec::new();
    for line in input.lines() {
        let line = line.to_string();
        results.push(line.clone()); // unnecessary clone
    }
    results.join("\\n")
}`,
    },
  ],
  java: [
    {
      label: 'SQL injection',
      language: 'java',
      code: `import java.sql.*;

public class UserService {
    private static final String DB_PASSWORD = "admin123"; // hardcoded!

    public User getUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // SQL injection
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE username = '" + username + "'");
        if (rs.next()) {
            return new User(rs.getString("name"));
        }
        return null; // TODO: throw exception
    }
}`,
    },
  ],
};

export function CodeInput({ code, language, isLoading, onCodeChange, onLanguageChange, onSubmit }: CodeInputProps) {
  const [sampleOpen, setSampleOpen] = useState(false);

  const handleLanguageChange = (e: ChangeEvent<HTMLSelectElement>) => {
    onLanguageChange(e.target.value as CodeInputProps['language']);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      onSubmit();
    }
  };

  const currentSamples = SAMPLE_CODE[language] || [];

  const loadSample = (sample: { code: string; language: CodeInputProps['language'] }) => {
    onLanguageChange(sample.language);
    onCodeChange(sample.code);
    setSampleOpen(false);
  };

  return (
    <div className="flex flex-col h-full gap-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <select
          value={language}
          onChange={handleLanguageChange}
          className="bg-gray-800 text-gray-200 border border-gray-700 rounded-lg px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent cursor-pointer"
        >
          {LANGUAGES.map(lang => (
            <option key={lang.value} value={lang.value}>
              {lang.label}
            </option>
          ))}
        </select>

        {/* Sample loader */}
        {currentSamples.length > 0 && (
          <div className="relative">
            <button
              onClick={() => setSampleOpen(o => !o)}
              className="flex items-center gap-1.5 px-3 py-2 text-xs text-gray-400 hover:text-gray-200 border border-gray-700 rounded-lg hover:border-gray-600 transition-all"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 10h16M4 14h16M4 18h16" />
              </svg>
              Try sample
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {sampleOpen && (
              <div className="absolute left-0 top-full mt-1 z-10 bg-gray-800 border border-gray-700 rounded-xl shadow-xl w-52 overflow-hidden">
                {currentSamples.map((sample, idx) => (
                  <button
                    key={idx}
                    onClick={() => loadSample(sample)}
                    className="w-full text-left px-4 py-2.5 text-sm text-gray-300 hover:bg-gray-700/60 transition-colors border-b border-gray-700/50 last:border-0"
                  >
                    <div className="font-medium text-gray-200">{sample.label}</div>
                    <div className="text-xs text-gray-500 mt-0.5">{sample.language}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <button
          onClick={onSubmit}
          disabled={isLoading || !code.trim()}
          className="ml-auto bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold px-5 py-2 rounded-lg text-sm transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-gray-900 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Reviewing...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              Review Code
              <kbd className="hidden sm:inline-flex items-center gap-0.5 text-[10px] bg-indigo-700/60 px-1.5 py-0.5 rounded font-mono opacity-80">
                ⌘↵
              </kbd>
            </>
          )}
        </button>
      </div>

      {/* Code textarea */}
      <div className="relative flex-1 min-h-0" onClick={() => setSampleOpen(false)}>
        <textarea
          value={code}
          onChange={e => onCodeChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Paste your code here, or choose a sample above..."
          spellCheck={false}
          className="w-full h-full bg-gray-950 text-gray-200 border border-gray-700/50 rounded-xl p-4 font-mono text-sm leading-relaxed resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 placeholder:text-gray-600 scrollbar-thin"
        />
        {code.length > 0 && (
          <div className="absolute bottom-3 right-4 text-xs text-gray-600 font-mono pointer-events-none">
            {code.split('\n').length} lines
          </div>
        )}
      </div>
    </div>
  );
}
