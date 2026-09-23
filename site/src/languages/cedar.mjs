/** Minimal TextMate grammar for Cedar policies and human-readable schemas. */
export const cedarLanguage = {
  name: "cedar",
  displayName: "Cedar",
  scopeName: "source.cedar",
  aliases: ["cedarschema"],
  patterns: [
    { include: "#comments" },
    { include: "#strings" },
    { include: "#keywords" },
    { include: "#constants" },
    { include: "#operators" },
    { include: "#types" },
    { include: "#punctuation" },
  ],
  repository: {
    comments: {
      patterns: [{ name: "comment.line.double-slash.cedar", match: "//.*$" }],
    },
    strings: {
      name: "string.quoted.double.cedar",
      begin: '"',
      end: '"',
      patterns: [{ name: "constant.character.escape.cedar", match: "\\\\." }],
    },
    keywords: {
      name: "keyword.control.cedar",
      match:
        "\\b(?:permit|forbid|when|unless|if|then|else|in|is|has|like|action|principal|resource|context|entity|namespace|type|appliesTo|extends)\\b",
    },
    constants: {
      name: "constant.language.cedar",
      match: "\\b(?:true|false)\\b",
    },
    operators: {
      name: "keyword.operator.cedar",
      match: "(?:==|!=|<=|>=|&&|\\|\\||->|[!<>])",
    },
    types: {
      name: "support.type.cedar",
      match: "\\b(?:Bool|Long|String|Set|Record|Entity)\\b",
    },
    punctuation: {
      name: "punctuation.cedar",
      match: "[{}()\\[\\],:;.]",
    },
  },
};
