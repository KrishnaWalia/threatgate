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

LIB_CP=""
for jar in lib/*.jar; do
  if [ -f "${jar}" ]; then
    if command -v cygpath >/dev/null 2>&1; then
      jar="$(cygpath -m "${jar}")"
    fi
    if [ -z "${LIB_CP}" ]; then
      LIB_CP="${jar}"
    else
      LIB_CP="${LIB_CP}${CP_SEP}${jar}"
    fi
  fi
done

if [ -z "${LIB_CP}" ] && [ -n "${MYSQL_JDBC_JAR:-}" ] && [ -f "${MYSQL_JDBC_JAR}" ]; then
  LIB_CP="${MYSQL_JDBC_JAR}"
  if command -v cygpath >/dev/null 2>&1; then
    LIB_CP="$(cygpath -m "${LIB_CP}")"
  fi
fi

mkdir -p bin data
JAVA_SOURCES="$(find src -name '*.java')"

CP="bin"
if [ -n "${LIB_CP}" ]; then
  CP="bin${CP_SEP}${LIB_CP}"
  "${JAVAC_BIN}" -cp "${LIB_CP}" -d bin -sourcepath src ${JAVA_SOURCES}
else
  "${JAVAC_BIN}" -d bin -sourcepath src ${JAVA_SOURCES}
fi

exec "${JAVA_BIN}" -cp "${CP}" "${MAIN_CLASS}" "$@"
