#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

MAIN_CLASS="com.threatgate.app.Main"
if [ "${1:-}" = "--test" ]; then
  MAIN_CLASS="com.threatgate.test.ThreatGateTestRunner"
  shift
fi

JAVAC_BIN="javac"
JAVA_BIN="java"
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/javac" ]; then
  JAVAC_BIN="${JAVA_HOME}/bin/javac"
  JAVA_BIN="${JAVA_HOME}/bin/java"
elif [ -x "/c/Program Files/Java/jdk-26.0.2/bin/javac.exe" ]; then
  JAVAC_BIN="/c/Program Files/Java/jdk-26.0.2/bin/javac.exe"
  JAVA_BIN="/c/Program Files/Java/jdk-26.0.2/bin/java.exe"
fi

CP_SEP=":"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    CP_SEP=";"
    ;;
esac

JDBC_JAR=""
if [ -n "${MYSQL_JDBC_JAR:-}" ] && [ -f "${MYSQL_JDBC_JAR}" ]; then
  JDBC_JAR="${MYSQL_JDBC_JAR}"
else
  for candidate in lib/mysql-connector-j-*.jar /d/jdbc/mysql-connector-j-26.10.0/mysql-connector-j-26.10.0.jar; do
    if [ -f "${candidate}" ]; then
      JDBC_JAR="${candidate}"
      break
    fi
  done
fi

if [ -n "${JDBC_JAR}" ] && command -v cygpath >/dev/null 2>&1; then
  JDBC_JAR="$(cygpath -m "${JDBC_JAR}")"
fi

mkdir -p bin data
JAVA_SOURCES="$(find src -name '*.java')"

CP="bin"
if [ -n "${JDBC_JAR}" ]; then
  CP="bin${CP_SEP}${JDBC_JAR}"
  "${JAVAC_BIN}" -cp "${JDBC_JAR}" -d bin -sourcepath src ${JAVA_SOURCES}
else
  "${JAVAC_BIN}" -d bin -sourcepath src ${JAVA_SOURCES}
fi

exec "${JAVA_BIN}" -cp "${CP}" "${MAIN_CLASS}" "$@"
