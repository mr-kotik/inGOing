# Contributing Guidelines

## Legal Disclaimer

This project is intended SOLELY for:
- Educational purposes
- Security research
- Testing and improving security of your OWN systems
- Learning about system administration and security concepts

Any contributions MUST comply with these purposes and applicable laws.

## How to Contribute

### 1. Preparation

1. Make sure you have read and agree with:
   - [README.md](README.md)
   - [SECURITY.md](SECURITY.md)
   - Legal Disclaimer in this document

2. Fork the repository
3. Clone your fork locally
4. Set up the remote repository:
```bash
git remote add upstream https://github.com/mr-kotik/inGOing.git
git fetch upstream
```

### 2. Making Changes

1. Create a new branch for your changes:
```bash
git checkout -b feature/your-feature-name
```

2. Follow coding standards:
   - Use `gofmt` for code formatting
   - Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
   - Add comments for complex algorithms
   - Maintain Windows and Linux compatibility

3. Required checks:
   - Code compiles without errors
   - All tests pass successfully
   - Linter shows no warnings
   - Documentation is updated

### 3. Submitting Changes

1. Commits should be atomic and meaningful:
```bash
git commit -m "Brief description of changes"
```

2. Update your branch:
```bash
git fetch upstream
git rebase upstream/main
```

3. Push changes to your fork:
```bash
git push origin feature/your-feature-name
```

4. Create Pull Request

### 4. Pull Request Rules

1. PR title should be informative
2. Description should include:
   - What was changed
   - Why it's necessary
   - How it works
   - Test scenarios

3. PR must not:
   - Violate legal disclaimer
   - Contain malicious code
   - Compromise security
   - Degrade performance

## Coding Standards

### 1. Formatting

- Use `gofmt`
- Indentation: 4 spaces
- Maximum line length: 100 characters
- Group imports
- Use camelCase for names

### 2. Documentation

- Document all public functions
- Update README.md as needed
- Add usage examples
- Describe complex algorithms

### 3. Testing

- Add unit tests
- Test edge cases
- Check performance
- Test on different platforms

### 4. Security

- Check input data
- Use safe functions
- Avoid vulnerabilities
- Follow the principle of least privilege

## Verification Process

1. Automated checks:
   - Compilation
   - Tests
   - Linter
   - Formatting check

2. Code review:
   - Security check
   - Performance analysis
   - Design evaluation
   - Documentation check

3. Testing:
   - Functional
   - Load
   - Cross-platform
   - Integration

## Bug Reports

1. Check existing issues
2. Use the bug report template
3. Provide:
   - System version
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Logs and screenshots

## Suggestions for Improvement

1. Describe the problem/need
2. Suggest a solution
3. Discuss alternatives
4. Evaluate impact on:
   - Performance
   - Security
   - Usability
   - Maintainability

## Communication

- Use Issues for discussions
- Be polite and constructive
- Ask questions
- Help other participants

## License

Make sure you understand and agree with the [project license](LICENSE).

## Contacts

- Issues: for questions and discussions
- Pull Requests: for proposing changes
- Email: for confidential questions

## Thanks

We appreciate every participant's contribution to the project! 