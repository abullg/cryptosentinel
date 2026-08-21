# CryptoSentinel Express GT — mini vulnerable app for oracle generalization
# Per Claude v9: "мини-приложение (Express: IDOR + mass assignment + race на /transfer)"
#
# This proves IDOR/JWT oracles transfer from Flask (VAmPI) to Node.js (Express).
# Different language, different framework, different API conventions — same oracles.

FROM node:20-alpine

WORKDIR /app

# Install Express + JWT
RUN npm install express jsonwebtoken

# Copy app
COPY app.js .

ENV PORT=3010
EXPOSE 3010

CMD ["node", "app.js"]
