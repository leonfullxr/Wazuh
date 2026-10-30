"use strict";
import { fullFormats } from "ajv-formats/dist/formats.js";
const codePointLength = (value) => Array.from(value).length;
export const validateAnswer = validate21;
const schema32 = {
  additionalProperties: false,
  properties: {
    blocks: { items: { $ref: "#/$defs/TopicAnswer" }, title: "Blocks", type: "array" },
    clarify: { anyOf: [{ $ref: "#/$defs/Clarify" }, { type: "null" }], default: null },
    environment_id: { $ref: "#/$defs/ContentId" },
    feedback_receipt: { maxLength: 8192, title: "Feedback Receipt", type: "string" },
    followup_id: {
      anyOf: [{ format: "uuid", type: "string" }, { type: "null" }],
      default: null,
      title: "Followup Id",
    },
    followup_revision: {
      anyOf: [{ type: "integer" }, { type: "null" }],
      default: null,
      title: "Followup Revision",
    },
    language: { enum: ["en", "es"], title: "Language", type: "string" },
    left_out: { items: { $ref: "#/$defs/LeftOut" }, title: "Left Out", type: "array" },
    message: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Message" },
    provenance: { $ref: "#/$defs/BuildProvenance" },
    question_id: { format: "uuid", title: "Question Id", type: "string" },
    schema_version: { const: "1", default: "1", title: "Schema Version", type: "string" },
    status: { $ref: "#/$defs/AnswerStatus" },
    trace_id: { title: "Trace Id", type: "string" },
  },
  required: [
    "question_id",
    "environment_id",
    "language",
    "status",
    "blocks",
    "left_out",
    "provenance",
    "trace_id",
    "feedback_receipt",
  ],
  title: "Answer",
  type: "object",
};
const schema35 = { pattern: "^[a-z][a-z0-9_-]{0,63}$", type: "string" };
const schema150 = {
  enum: ["answered", "partial", "clarify", "refused"],
  title: "AnswerStatus",
  type: "string",
};
const func1 = Object.prototype.hasOwnProperty;
const func2 = codePointLength;
const schema33 = {
  additionalProperties: false,
  properties: {
    checks: { items: { $ref: "#/$defs/CheckResult" }, title: "Checks", type: "array" },
    document: { anyOf: [{ $ref: "#/$defs/DocPointer" }, { type: "null" }], default: null },
    judgment: { $ref: "#/$defs/JudgmentResult" },
    missing: {
      items: { enum: ["public_document", "playbook"], type: "string" },
      title: "Missing",
      type: "array",
    },
    ordinal: { minimum: 0, title: "Ordinal", type: "integer" },
    tables: { items: { $ref: "#/$defs/FetchResult" }, title: "Tables", type: "array" },
    topic_id: { $ref: "#/$defs/TopicId" },
  },
  required: ["topic_id", "ordinal", "missing", "tables", "checks", "judgment"],
  title: "TopicAnswer",
  type: "object",
};
const schema34 = {
  additionalProperties: false,
  properties: {
    check_id: { $ref: "#/$defs/ContentId" },
    evidence_ids: { items: { $ref: "#/$defs/EvidenceId" }, title: "Evidence Ids", type: "array" },
    expectation_id: { anyOf: [{ $ref: "#/$defs/ContentId" }, { type: "null" }], default: null },
    label: { title: "Label", type: "string" },
    message: { title: "Message", type: "string" },
    outcome: { $ref: "#/$defs/CheckOutcome" },
    topic_id: { $ref: "#/$defs/TopicId" },
  },
  required: ["check_id", "topic_id", "label", "outcome", "evidence_ids", "message"],
  title: "CheckResult",
  type: "object",
};
const schema36 = { pattern: "^ev1_[0-9a-f]{64}$", type: "string" };
const schema38 = {
  enum: ["passed", "failed", "unknown", "denied", "not_configured"],
  title: "CheckOutcome",
  type: "string",
};
const pattern4 = new RegExp("^[a-z][a-z0-9_-]{0,63}$", "u");
const pattern5 = new RegExp("^ev1_[0-9a-f]{64}$", "u");
const schema39 = { anyOf: [{ $ref: "#/$defs/ContentId" }, { const: "_records", type: "string" }] };
function validate24(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate24.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  const _errs0 = errors;
  let valid0 = false;
  const _errs1 = errors;
  if (typeof data === "string") {
    if (!pattern4.test(data)) {
      const err0 = {
        instancePath,
        schemaPath: "#/$defs/ContentId/pattern",
        keyword: "pattern",
        params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
        message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
  } else {
    const err1 = {
      instancePath,
      schemaPath: "#/$defs/ContentId/type",
      keyword: "type",
      params: { type: "string" },
      message: "must be string",
    };
    if (vErrors === null) {
      vErrors = [err1];
    } else {
      vErrors.push(err1);
    }
    errors++;
  }
  var _valid0 = _errs1 === errors;
  valid0 = valid0 || _valid0;
  const _errs4 = errors;
  if (typeof data !== "string") {
    const err2 = {
      instancePath,
      schemaPath: "#/anyOf/1/type",
      keyword: "type",
      params: { type: "string" },
      message: "must be string",
    };
    if (vErrors === null) {
      vErrors = [err2];
    } else {
      vErrors.push(err2);
    }
    errors++;
  }
  if ("_records" !== data) {
    const err3 = {
      instancePath,
      schemaPath: "#/anyOf/1/const",
      keyword: "const",
      params: { allowedValue: "_records" },
      message: "must be equal to constant",
    };
    if (vErrors === null) {
      vErrors = [err3];
    } else {
      vErrors.push(err3);
    }
    errors++;
  }
  var _valid0 = _errs4 === errors;
  valid0 = valid0 || _valid0;
  if (!valid0) {
    const err4 = {
      instancePath,
      schemaPath: "#/anyOf",
      keyword: "anyOf",
      params: {},
      message: "must match a schema in anyOf",
    };
    if (vErrors === null) {
      vErrors = [err4];
    } else {
      vErrors.push(err4);
    }
    errors++;
  } else {
    errors = _errs0;
    if (vErrors !== null) {
      if (_errs0) {
        vErrors.length = _errs0;
      } else {
        vErrors = null;
      }
    }
  }
  validate24.errors = vErrors;
  return errors === 0;
}
validate24.evaluated = { dynamicProps: false, dynamicItems: false };
function validate23(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate23.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.check_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "check_id" },
        message: "must have required property '" + "check_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.topic_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.label === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "label" },
        message: "must have required property '" + "label" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.outcome === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "outcome" },
        message: "must have required property '" + "outcome" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.evidence_ids === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evidence_ids" },
        message: "must have required property '" + "evidence_ids" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.message === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "message" },
        message: "must have required property '" + "message" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "check_id" ||
          key0 === "evidence_ids" ||
          key0 === "expectation_id" ||
          key0 === "label" ||
          key0 === "message" ||
          key0 === "outcome" ||
          key0 === "topic_id"
        )
      ) {
        const err6 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.check_id !== undefined) {
      let data0 = data.check_id;
      if (typeof data0 === "string") {
        if (!pattern4.test(data0)) {
          const err7 = {
            instancePath: instancePath + "/check_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      } else {
        const err8 = {
          instancePath: instancePath + "/check_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.evidence_ids !== undefined) {
      let data1 = data.evidence_ids;
      if (Array.isArray(data1)) {
        const len0 = data1.length;
        for (let i0 = 0; i0 < len0; i0++) {
          let data2 = data1[i0];
          if (typeof data2 === "string") {
            if (!pattern5.test(data2)) {
              const err9 = {
                instancePath: instancePath + "/evidence_ids/" + i0,
                schemaPath: "#/$defs/EvidenceId/pattern",
                keyword: "pattern",
                params: { pattern: "^ev1_[0-9a-f]{64}$" },
                message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
              };
              if (vErrors === null) {
                vErrors = [err9];
              } else {
                vErrors.push(err9);
              }
              errors++;
            }
          } else {
            const err10 = {
              instancePath: instancePath + "/evidence_ids/" + i0,
              schemaPath: "#/$defs/EvidenceId/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
        }
      } else {
        const err11 = {
          instancePath: instancePath + "/evidence_ids",
          schemaPath: "#/properties/evidence_ids/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.expectation_id !== undefined) {
      let data3 = data.expectation_id;
      const _errs11 = errors;
      let valid5 = false;
      const _errs12 = errors;
      if (typeof data3 === "string") {
        if (!pattern4.test(data3)) {
          const err12 = {
            instancePath: instancePath + "/expectation_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err12];
          } else {
            vErrors.push(err12);
          }
          errors++;
        }
      } else {
        const err13 = {
          instancePath: instancePath + "/expectation_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
      var _valid0 = _errs12 === errors;
      valid5 = valid5 || _valid0;
      const _errs15 = errors;
      if (data3 !== null) {
        const err14 = {
          instancePath: instancePath + "/expectation_id",
          schemaPath: "#/properties/expectation_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
      var _valid0 = _errs15 === errors;
      valid5 = valid5 || _valid0;
      if (!valid5) {
        const err15 = {
          instancePath: instancePath + "/expectation_id",
          schemaPath: "#/properties/expectation_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      } else {
        errors = _errs11;
        if (vErrors !== null) {
          if (_errs11) {
            vErrors.length = _errs11;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.label !== undefined) {
      if (typeof data.label !== "string") {
        const err16 = {
          instancePath: instancePath + "/label",
          schemaPath: "#/properties/label/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
    }
    if (data.message !== undefined) {
      if (typeof data.message !== "string") {
        const err17 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
    }
    if (data.outcome !== undefined) {
      let data6 = data.outcome;
      if (typeof data6 !== "string") {
        const err18 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/$defs/CheckOutcome/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
      if (
        !(
          data6 === "passed" ||
          data6 === "failed" ||
          data6 === "unknown" ||
          data6 === "denied" ||
          data6 === "not_configured"
        )
      ) {
        const err19 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/$defs/CheckOutcome/enum",
          keyword: "enum",
          params: { allowedValues: schema38.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err20 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err20];
    } else {
      vErrors.push(err20);
    }
    errors++;
  }
  validate23.errors = vErrors;
  return errors === 0;
}
validate23.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema41 = {
  additionalProperties: false,
  properties: {
    anchor: { title: "Anchor", type: "string" },
    content_sha: { $ref: "#/$defs/GitSHA40" },
    document_id: { $ref: "#/$defs/ContentId" },
    document_sha256: { $ref: "#/$defs/SHA256" },
    heading: { title: "Heading", type: "string" },
    source_path: { title: "Source Path", type: "string" },
    url: { $ref: "#/$defs/HTTPSUrl" },
  },
  required: [
    "document_id",
    "source_path",
    "heading",
    "anchor",
    "url",
    "content_sha",
    "document_sha256",
  ],
  title: "DocPointer",
  type: "object",
};
const schema42 = { pattern: "^[0-9a-f]{40}$", type: "string" };
const schema44 = { pattern: "^[0-9a-f]{64}$", type: "string" };
const schema45 = { format: "uri", maxLength: 2083, minLength: 1, type: "string" };
const pattern8 = new RegExp("^[0-9a-f]{40}$", "u");
const pattern10 = new RegExp("^[0-9a-f]{64}$", "u");
const formats0 = fullFormats.uri;
function validate27(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate27.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.document_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "document_id" },
        message: "must have required property '" + "document_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.source_path === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "source_path" },
        message: "must have required property '" + "source_path" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.heading === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "heading" },
        message: "must have required property '" + "heading" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.anchor === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "anchor" },
        message: "must have required property '" + "anchor" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.url === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "url" },
        message: "must have required property '" + "url" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.content_sha === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "content_sha" },
        message: "must have required property '" + "content_sha" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.document_sha256 === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "document_sha256" },
        message: "must have required property '" + "document_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "anchor" ||
          key0 === "content_sha" ||
          key0 === "document_id" ||
          key0 === "document_sha256" ||
          key0 === "heading" ||
          key0 === "source_path" ||
          key0 === "url"
        )
      ) {
        const err7 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.anchor !== undefined) {
      if (typeof data.anchor !== "string") {
        const err8 = {
          instancePath: instancePath + "/anchor",
          schemaPath: "#/properties/anchor/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.content_sha !== undefined) {
      let data1 = data.content_sha;
      if (typeof data1 === "string") {
        if (!pattern8.test(data1)) {
          const err9 = {
            instancePath: instancePath + "/content_sha",
            schemaPath: "#/$defs/GitSHA40/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{40}$" },
            message: 'must match pattern "' + "^[0-9a-f]{40}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/content_sha",
          schemaPath: "#/$defs/GitSHA40/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.document_id !== undefined) {
      let data2 = data.document_id;
      if (typeof data2 === "string") {
        if (!pattern4.test(data2)) {
          const err11 = {
            instancePath: instancePath + "/document_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err11];
          } else {
            vErrors.push(err11);
          }
          errors++;
        }
      } else {
        const err12 = {
          instancePath: instancePath + "/document_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.document_sha256 !== undefined) {
      let data3 = data.document_sha256;
      if (typeof data3 === "string") {
        if (!pattern10.test(data3)) {
          const err13 = {
            instancePath: instancePath + "/document_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/document_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.heading !== undefined) {
      if (typeof data.heading !== "string") {
        const err15 = {
          instancePath: instancePath + "/heading",
          schemaPath: "#/properties/heading/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.source_path !== undefined) {
      if (typeof data.source_path !== "string") {
        const err16 = {
          instancePath: instancePath + "/source_path",
          schemaPath: "#/properties/source_path/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
    }
    if (data.url !== undefined) {
      let data6 = data.url;
      if (typeof data6 === "string") {
        if (func2(data6) > 2083) {
          const err17 = {
            instancePath: instancePath + "/url",
            schemaPath: "#/$defs/HTTPSUrl/maxLength",
            keyword: "maxLength",
            params: { limit: 2083 },
            message: "must NOT have more than 2083 characters",
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
        if (func2(data6) < 1) {
          const err18 = {
            instancePath: instancePath + "/url",
            schemaPath: "#/$defs/HTTPSUrl/minLength",
            keyword: "minLength",
            params: { limit: 1 },
            message: "must NOT have fewer than 1 characters",
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
        if (!formats0(data6)) {
          const err19 = {
            instancePath: instancePath + "/url",
            schemaPath: "#/$defs/HTTPSUrl/format",
            keyword: "format",
            params: { format: "uri" },
            message: 'must match format "' + "uri" + '"',
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
      } else {
        const err20 = {
          instancePath: instancePath + "/url",
          schemaPath: "#/$defs/HTTPSUrl/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
  } else {
    const err21 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err21];
    } else {
      vErrors.push(err21);
    }
    errors++;
  }
  validate27.errors = vErrors;
  return errors === 0;
}
validate27.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema46 = {
  additionalProperties: false,
  properties: {
    effort: { anyOf: [{ $ref: "#/$defs/Effort" }, { type: "null" }], default: null },
    message: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Message" },
    model_id: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Model Id" },
    removed: { items: { $ref: "#/$defs/RemovedFinding" }, title: "Removed", type: "array" },
    sentences: { items: { $ref: "#/$defs/RenderedFinding" }, title: "Sentences", type: "array" },
    state: { $ref: "#/$defs/JudgmentState" },
    usage: { anyOf: [{ $ref: "#/$defs/TokenUsage" }, { type: "null" }], default: null },
  },
  required: ["state", "sentences", "removed"],
  title: "JudgmentResult",
  type: "object",
};
const schema47 = {
  enum: ["low", "medium", "high", "xhigh", "max"],
  title: "Effort",
  type: "string",
};
const schema54 = {
  enum: [
    "not_requested",
    "validated",
    "denial",
    "ingestion_unconfirmed",
    "context_exceeded",
    "budget_exceeded",
    "model_unavailable",
    "guardrail_blocked",
    "invalid_output",
    "no_findings",
    "all_removed",
    "evidence_unavailable",
    "token_count_unavailable",
    "deadline_exceeded",
    "capacity_limited",
  ],
  title: "JudgmentState",
  type: "string",
};
const schema48 = {
  additionalProperties: false,
  properties: {
    candidate_sha256: { $ref: "#/$defs/SHA256" },
    finding_id: { title: "Finding Id", type: "string" },
    reason: { $ref: "#/$defs/RemovedReason" },
  },
  required: ["finding_id", "reason", "candidate_sha256"],
  title: "RemovedFinding",
  type: "object",
};
const schema50 = {
  enum: [
    "unknown_evidence",
    "cross_topic",
    "bad_binding",
    "unsupported_value",
    "unknown_template",
    "invalid_schema",
    "bad_relation",
    "failed_prerequisite",
    "duplicate_id",
  ],
  title: "RemovedReason",
  type: "string",
};
function validate30(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate30.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.finding_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "finding_id" },
        message: "must have required property '" + "finding_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.reason === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "reason" },
        message: "must have required property '" + "reason" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.candidate_sha256 === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "candidate_sha256" },
        message: "must have required property '" + "candidate_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "candidate_sha256" || key0 === "finding_id" || key0 === "reason")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.candidate_sha256 !== undefined) {
      let data0 = data.candidate_sha256;
      if (typeof data0 === "string") {
        if (!pattern10.test(data0)) {
          const err4 = {
            instancePath: instancePath + "/candidate_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err4];
          } else {
            vErrors.push(err4);
          }
          errors++;
        }
      } else {
        const err5 = {
          instancePath: instancePath + "/candidate_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.finding_id !== undefined) {
      if (typeof data.finding_id !== "string") {
        const err6 = {
          instancePath: instancePath + "/finding_id",
          schemaPath: "#/properties/finding_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.reason !== undefined) {
      let data2 = data.reason;
      if (typeof data2 !== "string") {
        const err7 = {
          instancePath: instancePath + "/reason",
          schemaPath: "#/$defs/RemovedReason/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
      if (
        !(
          data2 === "unknown_evidence" ||
          data2 === "cross_topic" ||
          data2 === "bad_binding" ||
          data2 === "unsupported_value" ||
          data2 === "unknown_template" ||
          data2 === "invalid_schema" ||
          data2 === "bad_relation" ||
          data2 === "failed_prerequisite" ||
          data2 === "duplicate_id"
        )
      ) {
        const err8 = {
          instancePath: instancePath + "/reason",
          schemaPath: "#/$defs/RemovedReason/enum",
          keyword: "enum",
          params: { allowedValues: schema50.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
  } else {
    const err9 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err9];
    } else {
      vErrors.push(err9);
    }
    errors++;
  }
  validate30.errors = vErrors;
  return errors === 0;
}
validate30.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema51 = {
  additionalProperties: false,
  properties: {
    evidence_ids: { items: { $ref: "#/$defs/EvidenceId" }, title: "Evidence Ids", type: "array" },
    finding_id: { $ref: "#/$defs/ContentId" },
    kind: { enum: ["observation", "hypothesis", "recommendation"], title: "Kind", type: "string" },
    text: { title: "Text", type: "string" },
  },
  required: ["finding_id", "kind", "text", "evidence_ids"],
  title: "RenderedFinding",
  type: "object",
};
function validate32(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate32.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.finding_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "finding_id" },
        message: "must have required property '" + "finding_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.kind === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "kind" },
        message: "must have required property '" + "kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.text === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "text" },
        message: "must have required property '" + "text" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.evidence_ids === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evidence_ids" },
        message: "must have required property '" + "evidence_ids" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(key0 === "evidence_ids" || key0 === "finding_id" || key0 === "kind" || key0 === "text")
      ) {
        const err4 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.evidence_ids !== undefined) {
      let data0 = data.evidence_ids;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          let data1 = data0[i0];
          if (typeof data1 === "string") {
            if (!pattern5.test(data1)) {
              const err5 = {
                instancePath: instancePath + "/evidence_ids/" + i0,
                schemaPath: "#/$defs/EvidenceId/pattern",
                keyword: "pattern",
                params: { pattern: "^ev1_[0-9a-f]{64}$" },
                message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
              };
              if (vErrors === null) {
                vErrors = [err5];
              } else {
                vErrors.push(err5);
              }
              errors++;
            }
          } else {
            const err6 = {
              instancePath: instancePath + "/evidence_ids/" + i0,
              schemaPath: "#/$defs/EvidenceId/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err6];
            } else {
              vErrors.push(err6);
            }
            errors++;
          }
        }
      } else {
        const err7 = {
          instancePath: instancePath + "/evidence_ids",
          schemaPath: "#/properties/evidence_ids/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.finding_id !== undefined) {
      let data2 = data.finding_id;
      if (typeof data2 === "string") {
        if (!pattern4.test(data2)) {
          const err8 = {
            instancePath: instancePath + "/finding_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err8];
          } else {
            vErrors.push(err8);
          }
          errors++;
        }
      } else {
        const err9 = {
          instancePath: instancePath + "/finding_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.kind !== undefined) {
      let data3 = data.kind;
      if (typeof data3 !== "string") {
        const err10 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      if (!(data3 === "observation" || data3 === "hypothesis" || data3 === "recommendation")) {
        const err11 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/enum",
          keyword: "enum",
          params: { allowedValues: schema51.properties.kind.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.text !== undefined) {
      if (typeof data.text !== "string") {
        const err12 = {
          instancePath: instancePath + "/text",
          schemaPath: "#/properties/text/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
  } else {
    const err13 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err13];
    } else {
      vErrors.push(err13);
    }
    errors++;
  }
  validate32.errors = vErrors;
  return errors === 0;
}
validate32.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema55 = {
  additionalProperties: false,
  properties: {
    cache_read_input_tokens: { minimum: 0, title: "Cache Read Input Tokens", type: "integer" },
    cache_write_input_tokens: { minimum: 0, title: "Cache Write Input Tokens", type: "integer" },
    input_tokens: { minimum: 0, title: "Input Tokens", type: "integer" },
    output_tokens: { minimum: 0, title: "Output Tokens", type: "integer" },
    reservation_id: { format: "uuid", title: "Reservation Id", type: "string" },
    reserved_tokens: { minimum: 0, title: "Reserved Tokens", type: "integer" },
    topic_id: { $ref: "#/$defs/TopicId" },
    total_input_tokens: { minimum: 0, title: "Total Input Tokens", type: "integer" },
  },
  required: [
    "topic_id",
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_write_input_tokens",
    "total_input_tokens",
    "reserved_tokens",
    "reservation_id",
  ],
  title: "TokenUsage",
  type: "object",
};
const formats2 = /^(?:urn:uuid:)?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
function validate34(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate34.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.topic_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.input_tokens === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "input_tokens" },
        message: "must have required property '" + "input_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.output_tokens === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "output_tokens" },
        message: "must have required property '" + "output_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.cache_read_input_tokens === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "cache_read_input_tokens" },
        message: "must have required property '" + "cache_read_input_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.cache_write_input_tokens === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "cache_write_input_tokens" },
        message: "must have required property '" + "cache_write_input_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.total_input_tokens === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "total_input_tokens" },
        message: "must have required property '" + "total_input_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.reserved_tokens === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "reserved_tokens" },
        message: "must have required property '" + "reserved_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.reservation_id === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "reservation_id" },
        message: "must have required property '" + "reservation_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "cache_read_input_tokens" ||
          key0 === "cache_write_input_tokens" ||
          key0 === "input_tokens" ||
          key0 === "output_tokens" ||
          key0 === "reservation_id" ||
          key0 === "reserved_tokens" ||
          key0 === "topic_id" ||
          key0 === "total_input_tokens"
        )
      ) {
        const err8 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.cache_read_input_tokens !== undefined) {
      let data0 = data.cache_read_input_tokens;
      if (!(typeof data0 == "number" && !(data0 % 1) && !isNaN(data0) && isFinite(data0))) {
        const err9 = {
          instancePath: instancePath + "/cache_read_input_tokens",
          schemaPath: "#/properties/cache_read_input_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
      if (typeof data0 == "number" && isFinite(data0)) {
        if (data0 < 0 || isNaN(data0)) {
          const err10 = {
            instancePath: instancePath + "/cache_read_input_tokens",
            schemaPath: "#/properties/cache_read_input_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
      }
    }
    if (data.cache_write_input_tokens !== undefined) {
      let data1 = data.cache_write_input_tokens;
      if (!(typeof data1 == "number" && !(data1 % 1) && !isNaN(data1) && isFinite(data1))) {
        const err11 = {
          instancePath: instancePath + "/cache_write_input_tokens",
          schemaPath: "#/properties/cache_write_input_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      if (typeof data1 == "number" && isFinite(data1)) {
        if (data1 < 0 || isNaN(data1)) {
          const err12 = {
            instancePath: instancePath + "/cache_write_input_tokens",
            schemaPath: "#/properties/cache_write_input_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err12];
          } else {
            vErrors.push(err12);
          }
          errors++;
        }
      }
    }
    if (data.input_tokens !== undefined) {
      let data2 = data.input_tokens;
      if (!(typeof data2 == "number" && !(data2 % 1) && !isNaN(data2) && isFinite(data2))) {
        const err13 = {
          instancePath: instancePath + "/input_tokens",
          schemaPath: "#/properties/input_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
      if (typeof data2 == "number" && isFinite(data2)) {
        if (data2 < 0 || isNaN(data2)) {
          const err14 = {
            instancePath: instancePath + "/input_tokens",
            schemaPath: "#/properties/input_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        }
      }
    }
    if (data.output_tokens !== undefined) {
      let data3 = data.output_tokens;
      if (!(typeof data3 == "number" && !(data3 % 1) && !isNaN(data3) && isFinite(data3))) {
        const err15 = {
          instancePath: instancePath + "/output_tokens",
          schemaPath: "#/properties/output_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
      if (typeof data3 == "number" && isFinite(data3)) {
        if (data3 < 0 || isNaN(data3)) {
          const err16 = {
            instancePath: instancePath + "/output_tokens",
            schemaPath: "#/properties/output_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err16];
          } else {
            vErrors.push(err16);
          }
          errors++;
        }
      }
    }
    if (data.reservation_id !== undefined) {
      let data4 = data.reservation_id;
      if (typeof data4 === "string") {
        if (!formats2.test(data4)) {
          const err17 = {
            instancePath: instancePath + "/reservation_id",
            schemaPath: "#/properties/reservation_id/format",
            keyword: "format",
            params: { format: "uuid" },
            message: 'must match format "' + "uuid" + '"',
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/reservation_id",
          schemaPath: "#/properties/reservation_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
    if (data.reserved_tokens !== undefined) {
      let data5 = data.reserved_tokens;
      if (!(typeof data5 == "number" && !(data5 % 1) && !isNaN(data5) && isFinite(data5))) {
        const err19 = {
          instancePath: instancePath + "/reserved_tokens",
          schemaPath: "#/properties/reserved_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
      if (typeof data5 == "number" && isFinite(data5)) {
        if (data5 < 0 || isNaN(data5)) {
          const err20 = {
            instancePath: instancePath + "/reserved_tokens",
            schemaPath: "#/properties/reserved_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err20];
          } else {
            vErrors.push(err20);
          }
          errors++;
        }
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
    if (data.total_input_tokens !== undefined) {
      let data7 = data.total_input_tokens;
      if (!(typeof data7 == "number" && !(data7 % 1) && !isNaN(data7) && isFinite(data7))) {
        const err21 = {
          instancePath: instancePath + "/total_input_tokens",
          schemaPath: "#/properties/total_input_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err21];
        } else {
          vErrors.push(err21);
        }
        errors++;
      }
      if (typeof data7 == "number" && isFinite(data7)) {
        if (data7 < 0 || isNaN(data7)) {
          const err22 = {
            instancePath: instancePath + "/total_input_tokens",
            schemaPath: "#/properties/total_input_tokens/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err22];
          } else {
            vErrors.push(err22);
          }
          errors++;
        }
      }
    }
  } else {
    const err23 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err23];
    } else {
      vErrors.push(err23);
    }
    errors++;
  }
  validate34.errors = vErrors;
  return errors === 0;
}
validate34.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate29(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate29.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.state === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "state" },
        message: "must have required property '" + "state" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.sentences === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "sentences" },
        message: "must have required property '" + "sentences" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.removed === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "removed" },
        message: "must have required property '" + "removed" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "effort" ||
          key0 === "message" ||
          key0 === "model_id" ||
          key0 === "removed" ||
          key0 === "sentences" ||
          key0 === "state" ||
          key0 === "usage"
        )
      ) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.effort !== undefined) {
      let data0 = data.effort;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (typeof data0 !== "string") {
        const err4 = {
          instancePath: instancePath + "/effort",
          schemaPath: "#/$defs/Effort/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (
        !(
          data0 === "low" ||
          data0 === "medium" ||
          data0 === "high" ||
          data0 === "xhigh" ||
          data0 === "max"
        )
      ) {
        const err5 = {
          instancePath: instancePath + "/effort",
          schemaPath: "#/$defs/Effort/enum",
          keyword: "enum",
          params: { allowedValues: schema47.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs7 = errors;
      if (data0 !== null) {
        const err6 = {
          instancePath: instancePath + "/effort",
          schemaPath: "#/properties/effort/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      var _valid0 = _errs7 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err7 = {
          instancePath: instancePath + "/effort",
          schemaPath: "#/properties/effort/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.message !== undefined) {
      let data1 = data.message;
      const _errs10 = errors;
      let valid3 = false;
      const _errs11 = errors;
      if (typeof data1 !== "string") {
        const err8 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      var _valid1 = _errs11 === errors;
      valid3 = valid3 || _valid1;
      const _errs13 = errors;
      if (data1 !== null) {
        const err9 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
      var _valid1 = _errs13 === errors;
      valid3 = valid3 || _valid1;
      if (!valid3) {
        const err10 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      } else {
        errors = _errs10;
        if (vErrors !== null) {
          if (_errs10) {
            vErrors.length = _errs10;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.model_id !== undefined) {
      let data2 = data.model_id;
      const _errs16 = errors;
      let valid4 = false;
      const _errs17 = errors;
      if (typeof data2 !== "string") {
        const err11 = {
          instancePath: instancePath + "/model_id",
          schemaPath: "#/properties/model_id/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid2 = _errs17 === errors;
      valid4 = valid4 || _valid2;
      const _errs19 = errors;
      if (data2 !== null) {
        const err12 = {
          instancePath: instancePath + "/model_id",
          schemaPath: "#/properties/model_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
      var _valid2 = _errs19 === errors;
      valid4 = valid4 || _valid2;
      if (!valid4) {
        const err13 = {
          instancePath: instancePath + "/model_id",
          schemaPath: "#/properties/model_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      } else {
        errors = _errs16;
        if (vErrors !== null) {
          if (_errs16) {
            vErrors.length = _errs16;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.removed !== undefined) {
      let data3 = data.removed;
      if (Array.isArray(data3)) {
        const len0 = data3.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate30(data3[i0], {
              instancePath: instancePath + "/removed/" + i0,
              parentData: data3,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate30.errors : vErrors.concat(validate30.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/removed",
          schemaPath: "#/properties/removed/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.sentences !== undefined) {
      let data5 = data.sentences;
      if (Array.isArray(data5)) {
        const len1 = data5.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate32(data5[i1], {
              instancePath: instancePath + "/sentences/" + i1,
              parentData: data5,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate32.errors : vErrors.concat(validate32.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/sentences",
          schemaPath: "#/properties/sentences/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.state !== undefined) {
      let data7 = data.state;
      if (typeof data7 !== "string") {
        const err16 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/JudgmentState/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
      if (
        !(
          data7 === "not_requested" ||
          data7 === "validated" ||
          data7 === "denial" ||
          data7 === "ingestion_unconfirmed" ||
          data7 === "context_exceeded" ||
          data7 === "budget_exceeded" ||
          data7 === "model_unavailable" ||
          data7 === "guardrail_blocked" ||
          data7 === "invalid_output" ||
          data7 === "no_findings" ||
          data7 === "all_removed" ||
          data7 === "evidence_unavailable" ||
          data7 === "token_count_unavailable" ||
          data7 === "deadline_exceeded" ||
          data7 === "capacity_limited"
        )
      ) {
        const err17 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/JudgmentState/enum",
          keyword: "enum",
          params: { allowedValues: schema54.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
    }
    if (data.usage !== undefined) {
      let data8 = data.usage;
      const _errs31 = errors;
      let valid10 = false;
      const _errs32 = errors;
      if (
        !validate34(data8, {
          instancePath: instancePath + "/usage",
          parentData: data,
          parentDataProperty: "usage",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate34.errors : vErrors.concat(validate34.errors);
        errors = vErrors.length;
      }
      var _valid3 = _errs32 === errors;
      valid10 = valid10 || _valid3;
      const _errs33 = errors;
      if (data8 !== null) {
        const err18 = {
          instancePath: instancePath + "/usage",
          schemaPath: "#/properties/usage/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
      var _valid3 = _errs33 === errors;
      valid10 = valid10 || _valid3;
      if (!valid10) {
        const err19 = {
          instancePath: instancePath + "/usage",
          schemaPath: "#/properties/usage/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      } else {
        errors = _errs31;
        if (vErrors !== null) {
          if (_errs31) {
            vErrors.length = _errs31;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err20 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err20];
    } else {
      vErrors.push(err20);
    }
    errors++;
  }
  validate29.errors = vErrors;
  return errors === 0;
}
validate29.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema56 = {
  additionalProperties: false,
  properties: {
    bucket_completeness: {
      default: "complete",
      enum: ["complete", "partial", "unknown"],
      title: "Bucket Completeness",
      type: "string",
    },
    buckets: { items: { $ref: "#/$defs/Bucket" }, title: "Buckets", type: "array" },
    checks: { items: { $ref: "#/$defs/EvidenceCheck" }, title: "Checks", type: "array" },
    columns: { items: { $ref: "#/$defs/Column" }, title: "Columns", type: "array" },
    count: { anyOf: [{ $ref: "#/$defs/Count" }, { type: "null" }], default: null },
    empty_proof: { anyOf: [{ $ref: "#/$defs/EmptyProof" }, { type: "null" }], default: null },
    error: { anyOf: [{ $ref: "#/$defs/DomainError" }, { type: "null" }], default: null },
    fetch_id: { $ref: "#/$defs/ContentId" },
    items: { items: { $ref: "#/$defs/EvidenceItem" }, title: "Items", type: "array" },
    message: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Message" },
    next_cursor: {
      anyOf: [{ type: "string" }, { type: "null" }],
      default: null,
      title: "Next Cursor",
    },
    rows: { items: { $ref: "#/$defs/EvidenceRow" }, title: "Rows", type: "array" },
    scope: { $ref: "#/$defs/FetchScope" },
    snapshot: { $ref: "#/$defs/SnapshotRef" },
    snapshot_at: { anyOf: [{ $ref: "#/$defs/UTCDateTime" }, { type: "null" }], default: null },
    state: { $ref: "#/$defs/FetchState" },
    topic_id: { $ref: "#/$defs/TopicId" },
    window: { $ref: "#/$defs/ResolvedWindow" },
  },
  required: [
    "fetch_id",
    "topic_id",
    "state",
    "scope",
    "window",
    "columns",
    "rows",
    "checks",
    "snapshot",
    "items",
  ],
  title: "FetchResult",
  type: "object",
};
const schema58 = {
  additionalProperties: false,
  properties: {
    approximate: { default: false, title: "Approximate", type: "boolean" },
    computed_by: { const: "indexer", title: "Computed By", type: "string" },
    relation: { enum: ["eq", "gte"], title: "Relation", type: "string" },
    scope: {
      enum: ["matching_visible_records", "bucket_visible_records"],
      title: "Scope",
      type: "string",
    },
    value: { minimum: 0, title: "Value", type: "integer" },
  },
  required: ["value", "relation", "scope", "computed_by"],
  title: "Count",
  type: "object",
};
const schema78 = { format: "date-time", type: "string" };
const schema138 = {
  enum: ["rows", "empty", "filtered", "denied", "unavailable"],
  title: "FetchState",
  type: "string",
};
const schema57 = {
  additionalProperties: false,
  properties: {
    count: { $ref: "#/$defs/Count" },
    evidence_id: { $ref: "#/$defs/EvidenceId" },
    key: { anyOf: [{ type: "string" }, { type: "integer" }], title: "Key" },
  },
  required: ["key", "count", "evidence_id"],
  title: "Bucket",
  type: "object",
};
function validate39(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate39.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.key === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "key" },
        message: "must have required property '" + "key" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.count === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "count" },
        message: "must have required property '" + "count" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.evidence_id === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evidence_id" },
        message: "must have required property '" + "evidence_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "count" || key0 === "evidence_id" || key0 === "key")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.count !== undefined) {
      let data0 = data.count;
      if (data0 && typeof data0 == "object" && !Array.isArray(data0)) {
        if (data0.value === undefined) {
          const err4 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "value" },
            message: "must have required property '" + "value" + "'",
          };
          if (vErrors === null) {
            vErrors = [err4];
          } else {
            vErrors.push(err4);
          }
          errors++;
        }
        if (data0.relation === undefined) {
          const err5 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "relation" },
            message: "must have required property '" + "relation" + "'",
          };
          if (vErrors === null) {
            vErrors = [err5];
          } else {
            vErrors.push(err5);
          }
          errors++;
        }
        if (data0.scope === undefined) {
          const err6 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "scope" },
            message: "must have required property '" + "scope" + "'",
          };
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
        if (data0.computed_by === undefined) {
          const err7 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "computed_by" },
            message: "must have required property '" + "computed_by" + "'",
          };
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
        for (const key1 in data0) {
          if (
            !(
              key1 === "approximate" ||
              key1 === "computed_by" ||
              key1 === "relation" ||
              key1 === "scope" ||
              key1 === "value"
            )
          ) {
            const err8 = {
              instancePath: instancePath + "/count",
              schemaPath: "#/$defs/Count/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err8];
            } else {
              vErrors.push(err8);
            }
            errors++;
          }
        }
        if (data0.approximate !== undefined) {
          if (typeof data0.approximate !== "boolean") {
            const err9 = {
              instancePath: instancePath + "/count/approximate",
              schemaPath: "#/$defs/Count/properties/approximate/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err9];
            } else {
              vErrors.push(err9);
            }
            errors++;
          }
        }
        if (data0.computed_by !== undefined) {
          let data2 = data0.computed_by;
          if (typeof data2 !== "string") {
            const err10 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
          if ("indexer" !== data2) {
            const err11 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/const",
              keyword: "const",
              params: { allowedValue: "indexer" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          }
        }
        if (data0.relation !== undefined) {
          let data3 = data0.relation;
          if (typeof data3 !== "string") {
            const err12 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
          if (!(data3 === "eq" || data3 === "gte")) {
            const err13 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.relation.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err13];
            } else {
              vErrors.push(err13);
            }
            errors++;
          }
        }
        if (data0.scope !== undefined) {
          let data4 = data0.scope;
          if (typeof data4 !== "string") {
            const err14 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err14];
            } else {
              vErrors.push(err14);
            }
            errors++;
          }
          if (!(data4 === "matching_visible_records" || data4 === "bucket_visible_records")) {
            const err15 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.scope.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err15];
            } else {
              vErrors.push(err15);
            }
            errors++;
          }
        }
        if (data0.value !== undefined) {
          let data5 = data0.value;
          if (!(typeof data5 == "number" && !(data5 % 1) && !isNaN(data5) && isFinite(data5))) {
            const err16 = {
              instancePath: instancePath + "/count/value",
              schemaPath: "#/$defs/Count/properties/value/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err16];
            } else {
              vErrors.push(err16);
            }
            errors++;
          }
          if (typeof data5 == "number" && isFinite(data5)) {
            if (data5 < 0 || isNaN(data5)) {
              const err17 = {
                instancePath: instancePath + "/count/value",
                schemaPath: "#/$defs/Count/properties/value/minimum",
                keyword: "minimum",
                params: { comparison: ">=", limit: 0 },
                message: "must be >= 0",
              };
              if (vErrors === null) {
                vErrors = [err17];
              } else {
                vErrors.push(err17);
              }
              errors++;
            }
          }
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/$defs/Count/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
    if (data.evidence_id !== undefined) {
      let data6 = data.evidence_id;
      if (typeof data6 === "string") {
        if (!pattern5.test(data6)) {
          const err19 = {
            instancePath: instancePath + "/evidence_id",
            schemaPath: "#/$defs/EvidenceId/pattern",
            keyword: "pattern",
            params: { pattern: "^ev1_[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
      } else {
        const err20 = {
          instancePath: instancePath + "/evidence_id",
          schemaPath: "#/$defs/EvidenceId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
    if (data.key !== undefined) {
      let data7 = data.key;
      const _errs20 = errors;
      let valid4 = false;
      const _errs21 = errors;
      if (typeof data7 !== "string") {
        const err21 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err21];
        } else {
          vErrors.push(err21);
        }
        errors++;
      }
      var _valid0 = _errs21 === errors;
      valid4 = valid4 || _valid0;
      const _errs23 = errors;
      if (!(typeof data7 == "number" && !(data7 % 1) && !isNaN(data7) && isFinite(data7))) {
        const err22 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf/1/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
      var _valid0 = _errs23 === errors;
      valid4 = valid4 || _valid0;
      if (!valid4) {
        const err23 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err23];
        } else {
          vErrors.push(err23);
        }
        errors++;
      } else {
        errors = _errs20;
        if (vErrors !== null) {
          if (_errs20) {
            vErrors.length = _errs20;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err24 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err24];
    } else {
      vErrors.push(err24);
    }
    errors++;
  }
  validate39.errors = vErrors;
  return errors === 0;
}
validate39.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema60 = {
  additionalProperties: false,
  properties: {
    code: { $ref: "#/$defs/ContentId" },
    name: {
      enum: [
        "policy",
        "mapping",
        "validate_query",
        "execute_as_analyst",
        "exact_count",
        "index_exists",
        "window_data",
        "filter_probe",
        "snapshot",
        "duplicate_source",
      ],
      title: "Name",
      type: "string",
    },
    outcome: { enum: ["passed", "unknown", "failed"], title: "Outcome", type: "string" },
  },
  required: ["name", "outcome", "code"],
  title: "EvidenceCheck",
  type: "object",
};
function validate41(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate41.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.name === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "name" },
        message: "must have required property '" + "name" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.outcome === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "outcome" },
        message: "must have required property '" + "outcome" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.code === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "code" },
        message: "must have required property '" + "code" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "code" || key0 === "name" || key0 === "outcome")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.code !== undefined) {
      let data0 = data.code;
      if (typeof data0 === "string") {
        if (!pattern4.test(data0)) {
          const err4 = {
            instancePath: instancePath + "/code",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err4];
          } else {
            vErrors.push(err4);
          }
          errors++;
        }
      } else {
        const err5 = {
          instancePath: instancePath + "/code",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.name !== undefined) {
      let data1 = data.name;
      if (typeof data1 !== "string") {
        const err6 = {
          instancePath: instancePath + "/name",
          schemaPath: "#/properties/name/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      if (
        !(
          data1 === "policy" ||
          data1 === "mapping" ||
          data1 === "validate_query" ||
          data1 === "execute_as_analyst" ||
          data1 === "exact_count" ||
          data1 === "index_exists" ||
          data1 === "window_data" ||
          data1 === "filter_probe" ||
          data1 === "snapshot" ||
          data1 === "duplicate_source"
        )
      ) {
        const err7 = {
          instancePath: instancePath + "/name",
          schemaPath: "#/properties/name/enum",
          keyword: "enum",
          params: { allowedValues: schema60.properties.name.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.outcome !== undefined) {
      let data2 = data.outcome;
      if (typeof data2 !== "string") {
        const err8 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/properties/outcome/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      if (!(data2 === "passed" || data2 === "unknown" || data2 === "failed")) {
        const err9 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/properties/outcome/enum",
          keyword: "enum",
          params: { allowedValues: schema60.properties.outcome.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
  } else {
    const err10 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err10];
    } else {
      vErrors.push(err10);
    }
    errors++;
  }
  validate41.errors = vErrors;
  return errors === 0;
}
validate41.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema62 = {
  additionalProperties: false,
  properties: {
    field: { $ref: "#/$defs/FieldId" },
    kind: { enum: ["text", "integer", "date", "ip"], title: "Kind", type: "string" },
    label: { $ref: "#/$defs/LocaleText" },
  },
  required: ["field", "label", "kind"],
  title: "Column",
  type: "object",
};
const schema63 = {
  enum: [
    "timestamp",
    "agent.id",
    "agent.name",
    "rule.id",
    "rule.level",
    "rule.groups",
    "data.srcip",
    "data.dstip",
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.detected_at",
    "package.name",
    "package.version",
  ],
  title: "FieldId",
  type: "string",
};
const schema64 = {
  additionalProperties: false,
  properties: { en: { title: "En", type: "string" }, es: { title: "Es", type: "string" } },
  required: ["en", "es"],
  title: "LocaleText",
  type: "object",
};
function validate43(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate43.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.field === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "field" },
        message: "must have required property '" + "field" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.label === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "label" },
        message: "must have required property '" + "label" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.kind === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "kind" },
        message: "must have required property '" + "kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "field" || key0 === "kind" || key0 === "label")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.field !== undefined) {
      let data0 = data.field;
      if (typeof data0 !== "string") {
        const err4 = {
          instancePath: instancePath + "/field",
          schemaPath: "#/$defs/FieldId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (
        !(
          data0 === "timestamp" ||
          data0 === "agent.id" ||
          data0 === "agent.name" ||
          data0 === "rule.id" ||
          data0 === "rule.level" ||
          data0 === "rule.groups" ||
          data0 === "data.srcip" ||
          data0 === "data.dstip" ||
          data0 === "vulnerability.id" ||
          data0 === "vulnerability.severity" ||
          data0 === "vulnerability.detected_at" ||
          data0 === "package.name" ||
          data0 === "package.version"
        )
      ) {
        const err5 = {
          instancePath: instancePath + "/field",
          schemaPath: "#/$defs/FieldId/enum",
          keyword: "enum",
          params: { allowedValues: schema63.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.kind !== undefined) {
      let data1 = data.kind;
      if (typeof data1 !== "string") {
        const err6 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      if (!(data1 === "text" || data1 === "integer" || data1 === "date" || data1 === "ip")) {
        const err7 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/enum",
          keyword: "enum",
          params: { allowedValues: schema62.properties.kind.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.label !== undefined) {
      let data2 = data.label;
      if (data2 && typeof data2 == "object" && !Array.isArray(data2)) {
        if (data2.en === undefined) {
          const err8 = {
            instancePath: instancePath + "/label",
            schemaPath: "#/$defs/LocaleText/required",
            keyword: "required",
            params: { missingProperty: "en" },
            message: "must have required property '" + "en" + "'",
          };
          if (vErrors === null) {
            vErrors = [err8];
          } else {
            vErrors.push(err8);
          }
          errors++;
        }
        if (data2.es === undefined) {
          const err9 = {
            instancePath: instancePath + "/label",
            schemaPath: "#/$defs/LocaleText/required",
            keyword: "required",
            params: { missingProperty: "es" },
            message: "must have required property '" + "es" + "'",
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
        for (const key1 in data2) {
          if (!(key1 === "en" || key1 === "es")) {
            const err10 = {
              instancePath: instancePath + "/label",
              schemaPath: "#/$defs/LocaleText/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
        }
        if (data2.en !== undefined) {
          if (typeof data2.en !== "string") {
            const err11 = {
              instancePath: instancePath + "/label/en",
              schemaPath: "#/$defs/LocaleText/properties/en/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          }
        }
        if (data2.es !== undefined) {
          if (typeof data2.es !== "string") {
            const err12 = {
              instancePath: instancePath + "/label/es",
              schemaPath: "#/$defs/LocaleText/properties/es/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
        }
      } else {
        const err13 = {
          instancePath: instancePath + "/label",
          schemaPath: "#/$defs/LocaleText/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
  } else {
    const err14 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err14];
    } else {
      vErrors.push(err14);
    }
    errors++;
  }
  validate43.errors = vErrors;
  return errors === 0;
}
validate43.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema66 = {
  additionalProperties: false,
  properties: {
    combination_zero: { default: false, title: "Combination Zero", type: "boolean" },
    consistency: { enum: ["coherent", "unconfirmed"], title: "Consistency", type: "string" },
    filter_probes: {
      items: { $ref: "#/$defs/FilterProbe" },
      title: "Filter Probes",
      type: "array",
    },
    index_exists: { enum: ["confirmed", "unknown"], title: "Index Exists", type: "string" },
    items: { items: { $ref: "#/$defs/EvidenceItem" }, title: "Items", type: "array" },
    matched_nothing: {
      items: { $ref: "#/$defs/FieldId" },
      title: "Matched Nothing",
      type: "array",
    },
    snapshot: { $ref: "#/$defs/SnapshotRef" },
    visibility: { $ref: "#/$defs/Visibility" },
    window_count: { anyOf: [{ $ref: "#/$defs/Count" }, { type: "null" }], default: null },
    window_has_data: {
      enum: ["confirmed", "unknown", "empty"],
      title: "Window Has Data",
      type: "string",
    },
  },
  required: [
    "index_exists",
    "window_has_data",
    "filter_probes",
    "matched_nothing",
    "visibility",
    "snapshot",
    "consistency",
    "items",
  ],
  title: "EmptyProof",
  type: "object",
};
const schema117 = { enum: ["full", "filtered", "unknown"], title: "Visibility", type: "string" };
const schema67 = {
  additionalProperties: false,
  properties: {
    count: { anyOf: [{ $ref: "#/$defs/Count" }, { type: "null" }], default: null },
    filter: { $ref: "#/$defs/Filter" },
    outcome: { enum: ["passed", "unknown"], title: "Outcome", type: "string" },
  },
  required: ["filter", "outcome"],
  title: "FilterProbe",
  type: "object",
};
const schema69 = {
  additionalProperties: false,
  properties: {
    field: { $ref: "#/$defs/FieldId" },
    op: { enum: ["eq", "in", "gte", "lte", "exists"], title: "Op", type: "string" },
    value: { $ref: "#/$defs/FilterValue" },
  },
  required: ["field", "op", "value"],
  title: "Filter",
  type: "object",
};
const schema71 = {
  anyOf: [
    { type: "string" },
    { type: "integer" },
    { items: { type: "string" }, type: "array" },
    { type: "null" },
  ],
};
function validate47(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate47.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.field === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "field" },
        message: "must have required property '" + "field" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.op === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "op" },
        message: "must have required property '" + "op" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.value === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "value" },
        message: "must have required property '" + "value" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "field" || key0 === "op" || key0 === "value")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.field !== undefined) {
      let data0 = data.field;
      if (typeof data0 !== "string") {
        const err4 = {
          instancePath: instancePath + "/field",
          schemaPath: "#/$defs/FieldId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (
        !(
          data0 === "timestamp" ||
          data0 === "agent.id" ||
          data0 === "agent.name" ||
          data0 === "rule.id" ||
          data0 === "rule.level" ||
          data0 === "rule.groups" ||
          data0 === "data.srcip" ||
          data0 === "data.dstip" ||
          data0 === "vulnerability.id" ||
          data0 === "vulnerability.severity" ||
          data0 === "vulnerability.detected_at" ||
          data0 === "package.name" ||
          data0 === "package.version"
        )
      ) {
        const err5 = {
          instancePath: instancePath + "/field",
          schemaPath: "#/$defs/FieldId/enum",
          keyword: "enum",
          params: { allowedValues: schema63.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.op !== undefined) {
      let data1 = data.op;
      if (typeof data1 !== "string") {
        const err6 = {
          instancePath: instancePath + "/op",
          schemaPath: "#/properties/op/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      if (
        !(
          data1 === "eq" ||
          data1 === "in" ||
          data1 === "gte" ||
          data1 === "lte" ||
          data1 === "exists"
        )
      ) {
        const err7 = {
          instancePath: instancePath + "/op",
          schemaPath: "#/properties/op/enum",
          keyword: "enum",
          params: { allowedValues: schema69.properties.op.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.value !== undefined) {
      let data2 = data.value;
      const _errs9 = errors;
      let valid3 = false;
      const _errs10 = errors;
      if (typeof data2 !== "string") {
        const err8 = {
          instancePath: instancePath + "/value",
          schemaPath: "#/$defs/FilterValue/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      var _valid0 = _errs10 === errors;
      valid3 = valid3 || _valid0;
      const _errs12 = errors;
      if (!(typeof data2 == "number" && !(data2 % 1) && !isNaN(data2) && isFinite(data2))) {
        const err9 = {
          instancePath: instancePath + "/value",
          schemaPath: "#/$defs/FilterValue/anyOf/1/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
      var _valid0 = _errs12 === errors;
      valid3 = valid3 || _valid0;
      const _errs14 = errors;
      if (Array.isArray(data2)) {
        const len0 = data2.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (typeof data2[i0] !== "string") {
            const err10 = {
              instancePath: instancePath + "/value/" + i0,
              schemaPath: "#/$defs/FilterValue/anyOf/2/items/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
        }
      } else {
        const err11 = {
          instancePath: instancePath + "/value",
          schemaPath: "#/$defs/FilterValue/anyOf/2/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid0 = _errs14 === errors;
      valid3 = valid3 || _valid0;
      const _errs18 = errors;
      if (data2 !== null) {
        const err12 = {
          instancePath: instancePath + "/value",
          schemaPath: "#/$defs/FilterValue/anyOf/3/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
      var _valid0 = _errs18 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err13 = {
          instancePath: instancePath + "/value",
          schemaPath: "#/$defs/FilterValue/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      } else {
        errors = _errs9;
        if (vErrors !== null) {
          if (_errs9) {
            vErrors.length = _errs9;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err14 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err14];
    } else {
      vErrors.push(err14);
    }
    errors++;
  }
  validate47.errors = vErrors;
  return errors === 0;
}
validate47.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate46(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate46.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.filter === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "filter" },
        message: "must have required property '" + "filter" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.outcome === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "outcome" },
        message: "must have required property '" + "outcome" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "count" || key0 === "filter" || key0 === "outcome")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.count !== undefined) {
      let data0 = data.count;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (data0 && typeof data0 == "object" && !Array.isArray(data0)) {
        if (data0.value === undefined) {
          const err3 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "value" },
            message: "must have required property '" + "value" + "'",
          };
          if (vErrors === null) {
            vErrors = [err3];
          } else {
            vErrors.push(err3);
          }
          errors++;
        }
        if (data0.relation === undefined) {
          const err4 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "relation" },
            message: "must have required property '" + "relation" + "'",
          };
          if (vErrors === null) {
            vErrors = [err4];
          } else {
            vErrors.push(err4);
          }
          errors++;
        }
        if (data0.scope === undefined) {
          const err5 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "scope" },
            message: "must have required property '" + "scope" + "'",
          };
          if (vErrors === null) {
            vErrors = [err5];
          } else {
            vErrors.push(err5);
          }
          errors++;
        }
        if (data0.computed_by === undefined) {
          const err6 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "computed_by" },
            message: "must have required property '" + "computed_by" + "'",
          };
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
        for (const key1 in data0) {
          if (
            !(
              key1 === "approximate" ||
              key1 === "computed_by" ||
              key1 === "relation" ||
              key1 === "scope" ||
              key1 === "value"
            )
          ) {
            const err7 = {
              instancePath: instancePath + "/count",
              schemaPath: "#/$defs/Count/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err7];
            } else {
              vErrors.push(err7);
            }
            errors++;
          }
        }
        if (data0.approximate !== undefined) {
          if (typeof data0.approximate !== "boolean") {
            const err8 = {
              instancePath: instancePath + "/count/approximate",
              schemaPath: "#/$defs/Count/properties/approximate/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err8];
            } else {
              vErrors.push(err8);
            }
            errors++;
          }
        }
        if (data0.computed_by !== undefined) {
          let data2 = data0.computed_by;
          if (typeof data2 !== "string") {
            const err9 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err9];
            } else {
              vErrors.push(err9);
            }
            errors++;
          }
          if ("indexer" !== data2) {
            const err10 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/const",
              keyword: "const",
              params: { allowedValue: "indexer" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
        }
        if (data0.relation !== undefined) {
          let data3 = data0.relation;
          if (typeof data3 !== "string") {
            const err11 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          }
          if (!(data3 === "eq" || data3 === "gte")) {
            const err12 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.relation.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
        }
        if (data0.scope !== undefined) {
          let data4 = data0.scope;
          if (typeof data4 !== "string") {
            const err13 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err13];
            } else {
              vErrors.push(err13);
            }
            errors++;
          }
          if (!(data4 === "matching_visible_records" || data4 === "bucket_visible_records")) {
            const err14 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.scope.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err14];
            } else {
              vErrors.push(err14);
            }
            errors++;
          }
        }
        if (data0.value !== undefined) {
          let data5 = data0.value;
          if (!(typeof data5 == "number" && !(data5 % 1) && !isNaN(data5) && isFinite(data5))) {
            const err15 = {
              instancePath: instancePath + "/count/value",
              schemaPath: "#/$defs/Count/properties/value/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err15];
            } else {
              vErrors.push(err15);
            }
            errors++;
          }
          if (typeof data5 == "number" && isFinite(data5)) {
            if (data5 < 0 || isNaN(data5)) {
              const err16 = {
                instancePath: instancePath + "/count/value",
                schemaPath: "#/$defs/Count/properties/value/minimum",
                keyword: "minimum",
                params: { comparison: ">=", limit: 0 },
                message: "must be >= 0",
              };
              if (vErrors === null) {
                vErrors = [err16];
              } else {
                vErrors.push(err16);
              }
              errors++;
            }
          }
        }
      } else {
        const err17 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/$defs/Count/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs18 = errors;
      if (data0 !== null) {
        const err18 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
      var _valid0 = _errs18 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err19 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.filter !== undefined) {
      if (
        !validate47(data.filter, {
          instancePath: instancePath + "/filter",
          parentData: data,
          parentDataProperty: "filter",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate47.errors : vErrors.concat(validate47.errors);
        errors = vErrors.length;
      }
    }
    if (data.outcome !== undefined) {
      let data7 = data.outcome;
      if (typeof data7 !== "string") {
        const err20 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/properties/outcome/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
      if (!(data7 === "passed" || data7 === "unknown")) {
        const err21 = {
          instancePath: instancePath + "/outcome",
          schemaPath: "#/properties/outcome/enum",
          keyword: "enum",
          params: { allowedValues: schema67.properties.outcome.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err21];
        } else {
          vErrors.push(err21);
        }
        errors++;
      }
    }
  } else {
    const err22 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err22];
    } else {
      vErrors.push(err22);
    }
    errors++;
  }
  validate46.errors = vErrors;
  return errors === 0;
}
validate46.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema72 = {
  additionalProperties: false,
  properties: {
    check_id: { anyOf: [{ $ref: "#/$defs/ContentId" }, { type: "null" }], default: null },
    evidence_id: { $ref: "#/$defs/EvidenceId" },
    fetch_id: { anyOf: [{ $ref: "#/$defs/ContentId" }, { type: "null" }], default: null },
    kind: { enum: ["row", "aggregate", "check", "context"], title: "Kind", type: "string" },
    scope_hash: { $ref: "#/$defs/SHA256" },
    snapshot: { $ref: "#/$defs/SnapshotRef" },
    source: { $ref: "#/$defs/EvidenceSource" },
    topic_id: { $ref: "#/$defs/TopicId" },
    values: {
      $ref: "#/$defs/EvidenceValues",
      additionalProperties: {
        anyOf: [
          { type: "string" },
          { type: "integer" },
          { type: "boolean" },
          { type: "null" },
          { items: { type: "string" }, type: "array" },
        ],
      },
      type: "object",
    },
    visibility: { $ref: "#/$defs/Visibility" },
  },
  required: [
    "evidence_id",
    "topic_id",
    "kind",
    "source",
    "snapshot",
    "values",
    "visibility",
    "scope_hash",
  ],
  title: "EvidenceItem",
  type: "object",
};
const schema77 = {
  additionalProperties: false,
  properties: {
    at: { $ref: "#/$defs/UTCDateTime" },
    expires_at: { anyOf: [{ $ref: "#/$defs/UTCDateTime" }, { type: "null" }], default: null },
    key: { $ref: "#/$defs/SHA256" },
    kind: { $ref: "#/$defs/SnapshotKind" },
  },
  required: ["kind", "key", "at"],
  title: "SnapshotRef",
  type: "object",
};
const schema81 = { enum: ["pit", "first_page_only"], title: "SnapshotKind", type: "string" };
const formats4 = fullFormats["date-time"];
function validate51(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate51.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.kind === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "kind" },
        message: "must have required property '" + "kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.key === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "key" },
        message: "must have required property '" + "key" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.at === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "at" },
        message: "must have required property '" + "at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "at" || key0 === "expires_at" || key0 === "key" || key0 === "kind")) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.at !== undefined) {
      let data0 = data.at;
      if (typeof data0 === "string") {
        if (!formats4.validate(data0)) {
          const err4 = {
            instancePath: instancePath + "/at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err4];
          } else {
            vErrors.push(err4);
          }
          errors++;
        }
      } else {
        const err5 = {
          instancePath: instancePath + "/at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.expires_at !== undefined) {
      let data1 = data.expires_at;
      const _errs6 = errors;
      let valid2 = false;
      const _errs7 = errors;
      if (typeof data1 === "string") {
        if (!formats4.validate(data1)) {
          const err6 = {
            instancePath: instancePath + "/expires_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
      } else {
        const err7 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
      var _valid0 = _errs7 === errors;
      valid2 = valid2 || _valid0;
      const _errs10 = errors;
      if (data1 !== null) {
        const err8 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/properties/expires_at/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      var _valid0 = _errs10 === errors;
      valid2 = valid2 || _valid0;
      if (!valid2) {
        const err9 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/properties/expires_at/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      } else {
        errors = _errs6;
        if (vErrors !== null) {
          if (_errs6) {
            vErrors.length = _errs6;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.key !== undefined) {
      let data2 = data.key;
      if (typeof data2 === "string") {
        if (!pattern10.test(data2)) {
          const err10 = {
            instancePath: instancePath + "/key",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
      } else {
        const err11 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.kind !== undefined) {
      let data3 = data.kind;
      if (typeof data3 !== "string") {
        const err12 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/$defs/SnapshotKind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
      if (!(data3 === "pit" || data3 === "first_page_only")) {
        const err13 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/$defs/SnapshotKind/enum",
          keyword: "enum",
          params: { allowedValues: schema81.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
  } else {
    const err14 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err14];
    } else {
      vErrors.push(err14);
    }
    errors++;
  }
  validate51.errors = vErrors;
  return errors === 0;
}
validate51.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema82 = {
  anyOf: [
    { $ref: "#/$defs/EvidenceSourceRow" },
    { $ref: "#/$defs/EvidenceSourceBucket" },
    { $ref: "#/$defs/EvidenceSourceCount" },
    { $ref: "#/$defs/EvidenceSourceProbe" },
    { $ref: "#/$defs/EvidenceSourceCheck" },
    { $ref: "#/$defs/EvidenceSourceContext" },
  ],
};
const schema83 = {
  additionalProperties: false,
  properties: {
    index_alias: { title: "Index Alias", type: "string" },
    record_id: { title: "Record Id", type: "string" },
  },
  required: ["index_alias", "record_id"],
  title: "EvidenceSourceRow",
  type: "object",
};
const schema84 = {
  additionalProperties: false,
  properties: {
    group_field: { $ref: "#/$defs/GroupField" },
    key: { anyOf: [{ type: "string" }, { type: "integer" }], title: "Key" },
  },
  required: ["group_field", "key"],
  title: "EvidenceSourceBucket",
  type: "object",
};
const schema85 = {
  enum: ["agent.id", "rule.id", "rule.level", "vulnerability.severity"],
  title: "GroupField",
  type: "string",
};
function validate54(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate54.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.group_field === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "group_field" },
        message: "must have required property '" + "group_field" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.key === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "key" },
        message: "must have required property '" + "key" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "group_field" || key0 === "key")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.group_field !== undefined) {
      let data0 = data.group_field;
      if (typeof data0 !== "string") {
        const err3 = {
          instancePath: instancePath + "/group_field",
          schemaPath: "#/$defs/GroupField/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
      if (
        !(
          data0 === "agent.id" ||
          data0 === "rule.id" ||
          data0 === "rule.level" ||
          data0 === "vulnerability.severity"
        )
      ) {
        const err4 = {
          instancePath: instancePath + "/group_field",
          schemaPath: "#/$defs/GroupField/enum",
          keyword: "enum",
          params: { allowedValues: schema85.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.key !== undefined) {
      let data1 = data.key;
      const _errs6 = errors;
      let valid2 = false;
      const _errs7 = errors;
      if (typeof data1 !== "string") {
        const err5 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
      var _valid0 = _errs7 === errors;
      valid2 = valid2 || _valid0;
      const _errs9 = errors;
      if (!(typeof data1 == "number" && !(data1 % 1) && !isNaN(data1) && isFinite(data1))) {
        const err6 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf/1/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      var _valid0 = _errs9 === errors;
      valid2 = valid2 || _valid0;
      if (!valid2) {
        const err7 = {
          instancePath: instancePath + "/key",
          schemaPath: "#/properties/key/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      } else {
        errors = _errs6;
        if (vErrors !== null) {
          if (_errs6) {
            vErrors.length = _errs6;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err8 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err8];
    } else {
      vErrors.push(err8);
    }
    errors++;
  }
  validate54.errors = vErrors;
  return errors === 0;
}
validate54.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema86 = {
  additionalProperties: false,
  properties: {
    filters: { items: { $ref: "#/$defs/Filter" }, title: "Filters", type: "array" },
    scope: { const: "matching_visible_records", title: "Scope", type: "string" },
    template_id: { $ref: "#/$defs/TemplateId" },
    window: { $ref: "#/$defs/ResolvedWindow" },
  },
  required: ["template_id", "window", "filters", "scope"],
  title: "EvidenceSourceCount",
  type: "object",
};
const schema87 = {
  enum: [
    "alerts_rows_v1",
    "alerts_count_v1",
    "alerts_group_v1",
    "vulnerabilities_rows_v1",
    "vulnerabilities_count_v1",
    "vulnerabilities_group_v1",
  ],
  title: "TemplateId",
  type: "string",
};
const schema88 = {
  additionalProperties: false,
  properties: {
    anchor_at: { $ref: "#/$defs/UTCDateTime" },
    end: { $ref: "#/$defs/UTCDateTime" },
    semantics: { enum: ["rolling", "calendar", "absolute"], title: "Semantics", type: "string" },
    source_text: { maxLength: 128, title: "Source Text", type: "string" },
    start: { $ref: "#/$defs/UTCDateTime" },
    timezone: { $ref: "#/$defs/IANAZone" },
  },
  required: ["start", "end", "semantics", "source_text", "timezone", "anchor_at"],
  title: "ResolvedWindow",
  type: "object",
};
const schema92 = {
  maxLength: 64,
  minLength: 1,
  pattern: "^[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*$",
  type: "string",
};
const pattern21 = new RegExp("^[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*$", "u");
function validate58(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate58.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.start === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "start" },
        message: "must have required property '" + "start" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.end === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "end" },
        message: "must have required property '" + "end" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.semantics === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "semantics" },
        message: "must have required property '" + "semantics" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.source_text === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "source_text" },
        message: "must have required property '" + "source_text" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.timezone === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "timezone" },
        message: "must have required property '" + "timezone" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.anchor_at === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "anchor_at" },
        message: "must have required property '" + "anchor_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "anchor_at" ||
          key0 === "end" ||
          key0 === "semantics" ||
          key0 === "source_text" ||
          key0 === "start" ||
          key0 === "timezone"
        )
      ) {
        const err6 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.anchor_at !== undefined) {
      let data0 = data.anchor_at;
      if (typeof data0 === "string") {
        if (!formats4.validate(data0)) {
          const err7 = {
            instancePath: instancePath + "/anchor_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      } else {
        const err8 = {
          instancePath: instancePath + "/anchor_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.end !== undefined) {
      let data1 = data.end;
      if (typeof data1 === "string") {
        if (!formats4.validate(data1)) {
          const err9 = {
            instancePath: instancePath + "/end",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/end",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.semantics !== undefined) {
      let data2 = data.semantics;
      if (typeof data2 !== "string") {
        const err11 = {
          instancePath: instancePath + "/semantics",
          schemaPath: "#/properties/semantics/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      if (!(data2 === "rolling" || data2 === "calendar" || data2 === "absolute")) {
        const err12 = {
          instancePath: instancePath + "/semantics",
          schemaPath: "#/properties/semantics/enum",
          keyword: "enum",
          params: { allowedValues: schema88.properties.semantics.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.source_text !== undefined) {
      let data3 = data.source_text;
      if (typeof data3 === "string") {
        if (func2(data3) > 128) {
          const err13 = {
            instancePath: instancePath + "/source_text",
            schemaPath: "#/properties/source_text/maxLength",
            keyword: "maxLength",
            params: { limit: 128 },
            message: "must NOT have more than 128 characters",
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/source_text",
          schemaPath: "#/properties/source_text/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.start !== undefined) {
      let data4 = data.start;
      if (typeof data4 === "string") {
        if (!formats4.validate(data4)) {
          const err15 = {
            instancePath: instancePath + "/start",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err15];
          } else {
            vErrors.push(err15);
          }
          errors++;
        }
      } else {
        const err16 = {
          instancePath: instancePath + "/start",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
    }
    if (data.timezone !== undefined) {
      let data5 = data.timezone;
      if (typeof data5 === "string") {
        if (func2(data5) > 64) {
          const err17 = {
            instancePath: instancePath + "/timezone",
            schemaPath: "#/$defs/IANAZone/maxLength",
            keyword: "maxLength",
            params: { limit: 64 },
            message: "must NOT have more than 64 characters",
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
        if (func2(data5) < 1) {
          const err18 = {
            instancePath: instancePath + "/timezone",
            schemaPath: "#/$defs/IANAZone/minLength",
            keyword: "minLength",
            params: { limit: 1 },
            message: "must NOT have fewer than 1 characters",
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
        if (!pattern21.test(data5)) {
          const err19 = {
            instancePath: instancePath + "/timezone",
            schemaPath: "#/$defs/IANAZone/pattern",
            keyword: "pattern",
            params: { pattern: "^[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*$" },
            message:
              'must match pattern "' + "^[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
      } else {
        const err20 = {
          instancePath: instancePath + "/timezone",
          schemaPath: "#/$defs/IANAZone/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
  } else {
    const err21 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err21];
    } else {
      vErrors.push(err21);
    }
    errors++;
  }
  validate58.errors = vErrors;
  return errors === 0;
}
validate58.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate56(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate56.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.template_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "template_id" },
        message: "must have required property '" + "template_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.window === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "window" },
        message: "must have required property '" + "window" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.filters === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "filters" },
        message: "must have required property '" + "filters" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.scope === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "scope" },
        message: "must have required property '" + "scope" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(key0 === "filters" || key0 === "scope" || key0 === "template_id" || key0 === "window")
      ) {
        const err4 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.filters !== undefined) {
      let data0 = data.filters;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate47(data0[i0], {
              instancePath: instancePath + "/filters/" + i0,
              parentData: data0,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate47.errors : vErrors.concat(validate47.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err5 = {
          instancePath: instancePath + "/filters",
          schemaPath: "#/properties/filters/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.scope !== undefined) {
      let data2 = data.scope;
      if (typeof data2 !== "string") {
        const err6 = {
          instancePath: instancePath + "/scope",
          schemaPath: "#/properties/scope/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      if ("matching_visible_records" !== data2) {
        const err7 = {
          instancePath: instancePath + "/scope",
          schemaPath: "#/properties/scope/const",
          keyword: "const",
          params: { allowedValue: "matching_visible_records" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.template_id !== undefined) {
      let data3 = data.template_id;
      if (typeof data3 !== "string") {
        const err8 = {
          instancePath: instancePath + "/template_id",
          schemaPath: "#/$defs/TemplateId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      if (
        !(
          data3 === "alerts_rows_v1" ||
          data3 === "alerts_count_v1" ||
          data3 === "alerts_group_v1" ||
          data3 === "vulnerabilities_rows_v1" ||
          data3 === "vulnerabilities_count_v1" ||
          data3 === "vulnerabilities_group_v1"
        )
      ) {
        const err9 = {
          instancePath: instancePath + "/template_id",
          schemaPath: "#/$defs/TemplateId/enum",
          keyword: "enum",
          params: { allowedValues: schema87.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.window !== undefined) {
      if (
        !validate58(data.window, {
          instancePath: instancePath + "/window",
          parentData: data,
          parentDataProperty: "window",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate58.errors : vErrors.concat(validate58.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err10 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err10];
    } else {
      vErrors.push(err10);
    }
    errors++;
  }
  validate56.errors = vErrors;
  return errors === 0;
}
validate56.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema93 = {
  additionalProperties: false,
  properties: {
    filters: { items: { $ref: "#/$defs/Filter" }, title: "Filters", type: "array" },
    probe_kind: {
      enum: ["index_exists", "window_data", "filter", "combination"],
      title: "Probe Kind",
      type: "string",
    },
  },
  required: ["probe_kind", "filters"],
  title: "EvidenceSourceProbe",
  type: "object",
};
function validate61(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate61.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.probe_kind === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "probe_kind" },
        message: "must have required property '" + "probe_kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.filters === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "filters" },
        message: "must have required property '" + "filters" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "filters" || key0 === "probe_kind")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.filters !== undefined) {
      let data0 = data.filters;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate47(data0[i0], {
              instancePath: instancePath + "/filters/" + i0,
              parentData: data0,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate47.errors : vErrors.concat(validate47.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err3 = {
          instancePath: instancePath + "/filters",
          schemaPath: "#/properties/filters/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.probe_kind !== undefined) {
      let data2 = data.probe_kind;
      if (typeof data2 !== "string") {
        const err4 = {
          instancePath: instancePath + "/probe_kind",
          schemaPath: "#/properties/probe_kind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (
        !(
          data2 === "index_exists" ||
          data2 === "window_data" ||
          data2 === "filter" ||
          data2 === "combination"
        )
      ) {
        const err5 = {
          instancePath: instancePath + "/probe_kind",
          schemaPath: "#/properties/probe_kind/enum",
          keyword: "enum",
          params: { allowedValues: schema93.properties.probe_kind.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
  } else {
    const err6 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err6];
    } else {
      vErrors.push(err6);
    }
    errors++;
  }
  validate61.errors = vErrors;
  return errors === 0;
}
validate61.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema94 = {
  additionalProperties: false,
  properties: {
    operand_ids: { items: { $ref: "#/$defs/EvidenceId" }, title: "Operand Ids", type: "array" },
    step_id: { $ref: "#/$defs/ContentId" },
  },
  required: ["step_id", "operand_ids"],
  title: "EvidenceSourceCheck",
  type: "object",
};
function validate64(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate64.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.step_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "step_id" },
        message: "must have required property '" + "step_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.operand_ids === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "operand_ids" },
        message: "must have required property '" + "operand_ids" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "operand_ids" || key0 === "step_id")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.operand_ids !== undefined) {
      let data0 = data.operand_ids;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          let data1 = data0[i0];
          if (typeof data1 === "string") {
            if (!pattern5.test(data1)) {
              const err3 = {
                instancePath: instancePath + "/operand_ids/" + i0,
                schemaPath: "#/$defs/EvidenceId/pattern",
                keyword: "pattern",
                params: { pattern: "^ev1_[0-9a-f]{64}$" },
                message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
              };
              if (vErrors === null) {
                vErrors = [err3];
              } else {
                vErrors.push(err3);
              }
              errors++;
            }
          } else {
            const err4 = {
              instancePath: instancePath + "/operand_ids/" + i0,
              schemaPath: "#/$defs/EvidenceId/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err4];
            } else {
              vErrors.push(err4);
            }
            errors++;
          }
        }
      } else {
        const err5 = {
          instancePath: instancePath + "/operand_ids",
          schemaPath: "#/properties/operand_ids/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.step_id !== undefined) {
      let data2 = data.step_id;
      if (typeof data2 === "string") {
        if (!pattern4.test(data2)) {
          const err6 = {
            instancePath: instancePath + "/step_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
      } else {
        const err7 = {
          instancePath: instancePath + "/step_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
  } else {
    const err8 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err8];
    } else {
      vErrors.push(err8);
    }
    errors++;
  }
  validate64.errors = vErrors;
  return errors === 0;
}
validate64.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema97 = {
  additionalProperties: false,
  properties: {
    kev_use: { anyOf: [{ $ref: "#/$defs/KevUseRef" }, { type: "null" }], default: null },
    member_index: {
      anyOf: [{ maximum: 63, minimum: 0, type: "integer" }, { type: "null" }],
      default: null,
      title: "Member Index",
    },
    page_evidence_id: { anyOf: [{ $ref: "#/$defs/EvidenceId" }, { type: "null" }], default: null },
    parent_evidence_id: {
      anyOf: [{ $ref: "#/$defs/EvidenceId" }, { type: "null" }],
      default: null,
    },
    role: { enum: ["page", "subject"], title: "Role", type: "string" },
  },
  required: ["role"],
  title: "EvidenceSourceContext",
  type: "object",
};
const schema98 = {
  additionalProperties: false,
  properties: {
    approval_key_id: { anyOf: [{ type: "string" }, { type: "null" }], title: "Approval Key Id" },
    approved_at: { anyOf: [{ $ref: "#/$defs/UTCDateTime" }, { type: "null" }] },
    content_sha: { $ref: "#/$defs/GitSHA40" },
    evaluation_at: { $ref: "#/$defs/UTCDateTime" },
    expires_at: { anyOf: [{ $ref: "#/$defs/UTCDateTime" }, { type: "null" }] },
    metadata: { anyOf: [{ $ref: "#/$defs/KevMetadata" }, { type: "null" }] },
    pack_sha256: { $ref: "#/$defs/SHA256" },
    policy_sha256: { $ref: "#/$defs/SHA256" },
    valid_from: { anyOf: [{ $ref: "#/$defs/UTCDateTime" }, { type: "null" }] },
  },
  required: [
    "content_sha",
    "pack_sha256",
    "metadata",
    "approved_at",
    "approval_key_id",
    "policy_sha256",
    "evaluation_at",
    "valid_from",
    "expires_at",
  ],
  title: "KevUseRef",
  type: "object",
};
const schema103 = {
  additionalProperties: false,
  properties: {
    catalog_version: { maxLength: 128, minLength: 1, title: "Catalog Version", type: "string" },
    dataset_id: { const: "cisa-kev", default: "cisa-kev", title: "Dataset Id", type: "string" },
    normalized_sha256: { $ref: "#/$defs/SHA256" },
    normalizer_version: {
      const: "cisa-kev/1",
      default: "cisa-kev/1",
      title: "Normalizer Version",
      type: "string",
    },
    notice: { $ref: "#/$defs/KevNotice" },
    policy: { $ref: "#/$defs/KevPolicy" },
    published_at: { $ref: "#/$defs/UTCDateTime" },
    raw_sha256: { $ref: "#/$defs/SHA256" },
    record_count: { maximum: 4096, minimum: 1, title: "Record Count", type: "integer" },
    retrieved_at: { $ref: "#/$defs/UTCDateTime" },
  },
  required: [
    "catalog_version",
    "record_count",
    "published_at",
    "retrieved_at",
    "raw_sha256",
    "normalized_sha256",
    "policy",
    "notice",
  ],
  title: "KevMetadata",
  type: "object",
};
const schema105 = {
  additionalProperties: false,
  properties: {
    attribution: { maxLength: 512, minLength: 1, title: "Attribution", type: "string" },
    source_url: { maxLength: 512, minLength: 1, title: "Source Url", type: "string" },
    terms_review_record: {
      maxLength: 512,
      minLength: 1,
      title: "Terms Review Record",
      type: "string",
    },
    terms_text: { minLength: 1, title: "Terms Text", type: "string" },
    terms_url: { maxLength: 512, minLength: 1, title: "Terms Url", type: "string" },
    transformations: { maxLength: 512, minLength: 1, title: "Transformations", type: "string" },
  },
  required: [
    "source_url",
    "terms_url",
    "attribution",
    "terms_text",
    "transformations",
    "terms_review_record",
  ],
  title: "KevNotice",
  type: "object",
};
const schema106 = {
  additionalProperties: false,
  properties: {
    fetch_id: { const: "vuln_rows", default: "vuln_rows", title: "Fetch Id", type: "string" },
    initial_context_bytes: {
      const: 98304,
      default: 98304,
      title: "Initial Context Bytes",
      type: "integer",
    },
    initial_context_items: {
      const: 512,
      default: 512,
      title: "Initial Context Items",
      type: "integer",
    },
    max_age_seconds: { const: 604800, default: 604800, title: "Max Age Seconds", type: "integer" },
    page_context_bytes: {
      const: 49152,
      default: 49152,
      title: "Page Context Bytes",
      type: "integer",
    },
    page_context_items: { const: 256, default: 256, title: "Page Context Items", type: "integer" },
    page_summary_bytes: {
      const: 16384,
      default: 16384,
      title: "Page Summary Bytes",
      type: "integer",
    },
    template_id: {
      const: "vulnerabilities_rows_v1",
      default: "vulnerabilities_rows_v1",
      title: "Template Id",
      type: "string",
    },
    topic_id: { const: "vuln_review", default: "vuln_review", title: "Topic Id", type: "string" },
  },
  title: "KevPolicy",
  type: "object",
};
function validate68(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate68.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.catalog_version === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "catalog_version" },
        message: "must have required property '" + "catalog_version" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.record_count === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "record_count" },
        message: "must have required property '" + "record_count" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.published_at === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "published_at" },
        message: "must have required property '" + "published_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.retrieved_at === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "retrieved_at" },
        message: "must have required property '" + "retrieved_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.raw_sha256 === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "raw_sha256" },
        message: "must have required property '" + "raw_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.normalized_sha256 === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "normalized_sha256" },
        message: "must have required property '" + "normalized_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.policy === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "policy" },
        message: "must have required property '" + "policy" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.notice === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "notice" },
        message: "must have required property '" + "notice" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema103.properties, key0)) {
        const err8 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.catalog_version !== undefined) {
      let data0 = data.catalog_version;
      if (typeof data0 === "string") {
        if (func2(data0) > 128) {
          const err9 = {
            instancePath: instancePath + "/catalog_version",
            schemaPath: "#/properties/catalog_version/maxLength",
            keyword: "maxLength",
            params: { limit: 128 },
            message: "must NOT have more than 128 characters",
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
        if (func2(data0) < 1) {
          const err10 = {
            instancePath: instancePath + "/catalog_version",
            schemaPath: "#/properties/catalog_version/minLength",
            keyword: "minLength",
            params: { limit: 1 },
            message: "must NOT have fewer than 1 characters",
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
      } else {
        const err11 = {
          instancePath: instancePath + "/catalog_version",
          schemaPath: "#/properties/catalog_version/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.dataset_id !== undefined) {
      let data1 = data.dataset_id;
      if (typeof data1 !== "string") {
        const err12 = {
          instancePath: instancePath + "/dataset_id",
          schemaPath: "#/properties/dataset_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
      if ("cisa-kev" !== data1) {
        const err13 = {
          instancePath: instancePath + "/dataset_id",
          schemaPath: "#/properties/dataset_id/const",
          keyword: "const",
          params: { allowedValue: "cisa-kev" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
    if (data.normalized_sha256 !== undefined) {
      let data2 = data.normalized_sha256;
      if (typeof data2 === "string") {
        if (!pattern10.test(data2)) {
          const err14 = {
            instancePath: instancePath + "/normalized_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/normalized_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.normalizer_version !== undefined) {
      let data3 = data.normalizer_version;
      if (typeof data3 !== "string") {
        const err16 = {
          instancePath: instancePath + "/normalizer_version",
          schemaPath: "#/properties/normalizer_version/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
      if ("cisa-kev/1" !== data3) {
        const err17 = {
          instancePath: instancePath + "/normalizer_version",
          schemaPath: "#/properties/normalizer_version/const",
          keyword: "const",
          params: { allowedValue: "cisa-kev/1" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
    }
    if (data.notice !== undefined) {
      let data4 = data.notice;
      if (data4 && typeof data4 == "object" && !Array.isArray(data4)) {
        if (data4.source_url === undefined) {
          const err18 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "source_url" },
            message: "must have required property '" + "source_url" + "'",
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
        if (data4.terms_url === undefined) {
          const err19 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "terms_url" },
            message: "must have required property '" + "terms_url" + "'",
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
        if (data4.attribution === undefined) {
          const err20 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "attribution" },
            message: "must have required property '" + "attribution" + "'",
          };
          if (vErrors === null) {
            vErrors = [err20];
          } else {
            vErrors.push(err20);
          }
          errors++;
        }
        if (data4.terms_text === undefined) {
          const err21 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "terms_text" },
            message: "must have required property '" + "terms_text" + "'",
          };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
        }
        if (data4.transformations === undefined) {
          const err22 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "transformations" },
            message: "must have required property '" + "transformations" + "'",
          };
          if (vErrors === null) {
            vErrors = [err22];
          } else {
            vErrors.push(err22);
          }
          errors++;
        }
        if (data4.terms_review_record === undefined) {
          const err23 = {
            instancePath: instancePath + "/notice",
            schemaPath: "#/$defs/KevNotice/required",
            keyword: "required",
            params: { missingProperty: "terms_review_record" },
            message: "must have required property '" + "terms_review_record" + "'",
          };
          if (vErrors === null) {
            vErrors = [err23];
          } else {
            vErrors.push(err23);
          }
          errors++;
        }
        for (const key1 in data4) {
          if (
            !(
              key1 === "attribution" ||
              key1 === "source_url" ||
              key1 === "terms_review_record" ||
              key1 === "terms_text" ||
              key1 === "terms_url" ||
              key1 === "transformations"
            )
          ) {
            const err24 = {
              instancePath: instancePath + "/notice",
              schemaPath: "#/$defs/KevNotice/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
          }
        }
        if (data4.attribution !== undefined) {
          let data5 = data4.attribution;
          if (typeof data5 === "string") {
            if (func2(data5) > 512) {
              const err25 = {
                instancePath: instancePath + "/notice/attribution",
                schemaPath: "#/$defs/KevNotice/properties/attribution/maxLength",
                keyword: "maxLength",
                params: { limit: 512 },
                message: "must NOT have more than 512 characters",
              };
              if (vErrors === null) {
                vErrors = [err25];
              } else {
                vErrors.push(err25);
              }
              errors++;
            }
            if (func2(data5) < 1) {
              const err26 = {
                instancePath: instancePath + "/notice/attribution",
                schemaPath: "#/$defs/KevNotice/properties/attribution/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err26];
              } else {
                vErrors.push(err26);
              }
              errors++;
            }
          } else {
            const err27 = {
              instancePath: instancePath + "/notice/attribution",
              schemaPath: "#/$defs/KevNotice/properties/attribution/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err27];
            } else {
              vErrors.push(err27);
            }
            errors++;
          }
        }
        if (data4.source_url !== undefined) {
          let data6 = data4.source_url;
          if (typeof data6 === "string") {
            if (func2(data6) > 512) {
              const err28 = {
                instancePath: instancePath + "/notice/source_url",
                schemaPath: "#/$defs/KevNotice/properties/source_url/maxLength",
                keyword: "maxLength",
                params: { limit: 512 },
                message: "must NOT have more than 512 characters",
              };
              if (vErrors === null) {
                vErrors = [err28];
              } else {
                vErrors.push(err28);
              }
              errors++;
            }
            if (func2(data6) < 1) {
              const err29 = {
                instancePath: instancePath + "/notice/source_url",
                schemaPath: "#/$defs/KevNotice/properties/source_url/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err29];
              } else {
                vErrors.push(err29);
              }
              errors++;
            }
          } else {
            const err30 = {
              instancePath: instancePath + "/notice/source_url",
              schemaPath: "#/$defs/KevNotice/properties/source_url/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err30];
            } else {
              vErrors.push(err30);
            }
            errors++;
          }
        }
        if (data4.terms_review_record !== undefined) {
          let data7 = data4.terms_review_record;
          if (typeof data7 === "string") {
            if (func2(data7) > 512) {
              const err31 = {
                instancePath: instancePath + "/notice/terms_review_record",
                schemaPath: "#/$defs/KevNotice/properties/terms_review_record/maxLength",
                keyword: "maxLength",
                params: { limit: 512 },
                message: "must NOT have more than 512 characters",
              };
              if (vErrors === null) {
                vErrors = [err31];
              } else {
                vErrors.push(err31);
              }
              errors++;
            }
            if (func2(data7) < 1) {
              const err32 = {
                instancePath: instancePath + "/notice/terms_review_record",
                schemaPath: "#/$defs/KevNotice/properties/terms_review_record/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err32];
              } else {
                vErrors.push(err32);
              }
              errors++;
            }
          } else {
            const err33 = {
              instancePath: instancePath + "/notice/terms_review_record",
              schemaPath: "#/$defs/KevNotice/properties/terms_review_record/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err33];
            } else {
              vErrors.push(err33);
            }
            errors++;
          }
        }
        if (data4.terms_text !== undefined) {
          let data8 = data4.terms_text;
          if (typeof data8 === "string") {
            if (func2(data8) < 1) {
              const err34 = {
                instancePath: instancePath + "/notice/terms_text",
                schemaPath: "#/$defs/KevNotice/properties/terms_text/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err34];
              } else {
                vErrors.push(err34);
              }
              errors++;
            }
          } else {
            const err35 = {
              instancePath: instancePath + "/notice/terms_text",
              schemaPath: "#/$defs/KevNotice/properties/terms_text/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err35];
            } else {
              vErrors.push(err35);
            }
            errors++;
          }
        }
        if (data4.terms_url !== undefined) {
          let data9 = data4.terms_url;
          if (typeof data9 === "string") {
            if (func2(data9) > 512) {
              const err36 = {
                instancePath: instancePath + "/notice/terms_url",
                schemaPath: "#/$defs/KevNotice/properties/terms_url/maxLength",
                keyword: "maxLength",
                params: { limit: 512 },
                message: "must NOT have more than 512 characters",
              };
              if (vErrors === null) {
                vErrors = [err36];
              } else {
                vErrors.push(err36);
              }
              errors++;
            }
            if (func2(data9) < 1) {
              const err37 = {
                instancePath: instancePath + "/notice/terms_url",
                schemaPath: "#/$defs/KevNotice/properties/terms_url/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err37];
              } else {
                vErrors.push(err37);
              }
              errors++;
            }
          } else {
            const err38 = {
              instancePath: instancePath + "/notice/terms_url",
              schemaPath: "#/$defs/KevNotice/properties/terms_url/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err38];
            } else {
              vErrors.push(err38);
            }
            errors++;
          }
        }
        if (data4.transformations !== undefined) {
          let data10 = data4.transformations;
          if (typeof data10 === "string") {
            if (func2(data10) > 512) {
              const err39 = {
                instancePath: instancePath + "/notice/transformations",
                schemaPath: "#/$defs/KevNotice/properties/transformations/maxLength",
                keyword: "maxLength",
                params: { limit: 512 },
                message: "must NOT have more than 512 characters",
              };
              if (vErrors === null) {
                vErrors = [err39];
              } else {
                vErrors.push(err39);
              }
              errors++;
            }
            if (func2(data10) < 1) {
              const err40 = {
                instancePath: instancePath + "/notice/transformations",
                schemaPath: "#/$defs/KevNotice/properties/transformations/minLength",
                keyword: "minLength",
                params: { limit: 1 },
                message: "must NOT have fewer than 1 characters",
              };
              if (vErrors === null) {
                vErrors = [err40];
              } else {
                vErrors.push(err40);
              }
              errors++;
            }
          } else {
            const err41 = {
              instancePath: instancePath + "/notice/transformations",
              schemaPath: "#/$defs/KevNotice/properties/transformations/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err41];
            } else {
              vErrors.push(err41);
            }
            errors++;
          }
        }
      } else {
        const err42 = {
          instancePath: instancePath + "/notice",
          schemaPath: "#/$defs/KevNotice/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err42];
        } else {
          vErrors.push(err42);
        }
        errors++;
      }
    }
    if (data.policy !== undefined) {
      let data11 = data.policy;
      if (data11 && typeof data11 == "object" && !Array.isArray(data11)) {
        for (const key2 in data11) {
          if (!func1.call(schema106.properties, key2)) {
            const err43 = {
              instancePath: instancePath + "/policy",
              schemaPath: "#/$defs/KevPolicy/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key2 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err43];
            } else {
              vErrors.push(err43);
            }
            errors++;
          }
        }
        if (data11.fetch_id !== undefined) {
          let data12 = data11.fetch_id;
          if (typeof data12 !== "string") {
            const err44 = {
              instancePath: instancePath + "/policy/fetch_id",
              schemaPath: "#/$defs/KevPolicy/properties/fetch_id/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err44];
            } else {
              vErrors.push(err44);
            }
            errors++;
          }
          if ("vuln_rows" !== data12) {
            const err45 = {
              instancePath: instancePath + "/policy/fetch_id",
              schemaPath: "#/$defs/KevPolicy/properties/fetch_id/const",
              keyword: "const",
              params: { allowedValue: "vuln_rows" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err45];
            } else {
              vErrors.push(err45);
            }
            errors++;
          }
        }
        if (data11.initial_context_bytes !== undefined) {
          let data13 = data11.initial_context_bytes;
          if (!(typeof data13 == "number" && !(data13 % 1) && !isNaN(data13) && isFinite(data13))) {
            const err46 = {
              instancePath: instancePath + "/policy/initial_context_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/initial_context_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err46];
            } else {
              vErrors.push(err46);
            }
            errors++;
          }
          if (98304 !== data13) {
            const err47 = {
              instancePath: instancePath + "/policy/initial_context_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/initial_context_bytes/const",
              keyword: "const",
              params: { allowedValue: 98304 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err47];
            } else {
              vErrors.push(err47);
            }
            errors++;
          }
        }
        if (data11.initial_context_items !== undefined) {
          let data14 = data11.initial_context_items;
          if (!(typeof data14 == "number" && !(data14 % 1) && !isNaN(data14) && isFinite(data14))) {
            const err48 = {
              instancePath: instancePath + "/policy/initial_context_items",
              schemaPath: "#/$defs/KevPolicy/properties/initial_context_items/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err48];
            } else {
              vErrors.push(err48);
            }
            errors++;
          }
          if (512 !== data14) {
            const err49 = {
              instancePath: instancePath + "/policy/initial_context_items",
              schemaPath: "#/$defs/KevPolicy/properties/initial_context_items/const",
              keyword: "const",
              params: { allowedValue: 512 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err49];
            } else {
              vErrors.push(err49);
            }
            errors++;
          }
        }
        if (data11.max_age_seconds !== undefined) {
          let data15 = data11.max_age_seconds;
          if (!(typeof data15 == "number" && !(data15 % 1) && !isNaN(data15) && isFinite(data15))) {
            const err50 = {
              instancePath: instancePath + "/policy/max_age_seconds",
              schemaPath: "#/$defs/KevPolicy/properties/max_age_seconds/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err50];
            } else {
              vErrors.push(err50);
            }
            errors++;
          }
          if (604800 !== data15) {
            const err51 = {
              instancePath: instancePath + "/policy/max_age_seconds",
              schemaPath: "#/$defs/KevPolicy/properties/max_age_seconds/const",
              keyword: "const",
              params: { allowedValue: 604800 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err51];
            } else {
              vErrors.push(err51);
            }
            errors++;
          }
        }
        if (data11.page_context_bytes !== undefined) {
          let data16 = data11.page_context_bytes;
          if (!(typeof data16 == "number" && !(data16 % 1) && !isNaN(data16) && isFinite(data16))) {
            const err52 = {
              instancePath: instancePath + "/policy/page_context_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/page_context_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err52];
            } else {
              vErrors.push(err52);
            }
            errors++;
          }
          if (49152 !== data16) {
            const err53 = {
              instancePath: instancePath + "/policy/page_context_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/page_context_bytes/const",
              keyword: "const",
              params: { allowedValue: 49152 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err53];
            } else {
              vErrors.push(err53);
            }
            errors++;
          }
        }
        if (data11.page_context_items !== undefined) {
          let data17 = data11.page_context_items;
          if (!(typeof data17 == "number" && !(data17 % 1) && !isNaN(data17) && isFinite(data17))) {
            const err54 = {
              instancePath: instancePath + "/policy/page_context_items",
              schemaPath: "#/$defs/KevPolicy/properties/page_context_items/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err54];
            } else {
              vErrors.push(err54);
            }
            errors++;
          }
          if (256 !== data17) {
            const err55 = {
              instancePath: instancePath + "/policy/page_context_items",
              schemaPath: "#/$defs/KevPolicy/properties/page_context_items/const",
              keyword: "const",
              params: { allowedValue: 256 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err55];
            } else {
              vErrors.push(err55);
            }
            errors++;
          }
        }
        if (data11.page_summary_bytes !== undefined) {
          let data18 = data11.page_summary_bytes;
          if (!(typeof data18 == "number" && !(data18 % 1) && !isNaN(data18) && isFinite(data18))) {
            const err56 = {
              instancePath: instancePath + "/policy/page_summary_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/page_summary_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err56];
            } else {
              vErrors.push(err56);
            }
            errors++;
          }
          if (16384 !== data18) {
            const err57 = {
              instancePath: instancePath + "/policy/page_summary_bytes",
              schemaPath: "#/$defs/KevPolicy/properties/page_summary_bytes/const",
              keyword: "const",
              params: { allowedValue: 16384 },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err57];
            } else {
              vErrors.push(err57);
            }
            errors++;
          }
        }
        if (data11.template_id !== undefined) {
          let data19 = data11.template_id;
          if (typeof data19 !== "string") {
            const err58 = {
              instancePath: instancePath + "/policy/template_id",
              schemaPath: "#/$defs/KevPolicy/properties/template_id/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err58];
            } else {
              vErrors.push(err58);
            }
            errors++;
          }
          if ("vulnerabilities_rows_v1" !== data19) {
            const err59 = {
              instancePath: instancePath + "/policy/template_id",
              schemaPath: "#/$defs/KevPolicy/properties/template_id/const",
              keyword: "const",
              params: { allowedValue: "vulnerabilities_rows_v1" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err59];
            } else {
              vErrors.push(err59);
            }
            errors++;
          }
        }
        if (data11.topic_id !== undefined) {
          let data20 = data11.topic_id;
          if (typeof data20 !== "string") {
            const err60 = {
              instancePath: instancePath + "/policy/topic_id",
              schemaPath: "#/$defs/KevPolicy/properties/topic_id/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err60];
            } else {
              vErrors.push(err60);
            }
            errors++;
          }
          if ("vuln_review" !== data20) {
            const err61 = {
              instancePath: instancePath + "/policy/topic_id",
              schemaPath: "#/$defs/KevPolicy/properties/topic_id/const",
              keyword: "const",
              params: { allowedValue: "vuln_review" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err61];
            } else {
              vErrors.push(err61);
            }
            errors++;
          }
        }
      } else {
        const err62 = {
          instancePath: instancePath + "/policy",
          schemaPath: "#/$defs/KevPolicy/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err62];
        } else {
          vErrors.push(err62);
        }
        errors++;
      }
    }
    if (data.published_at !== undefined) {
      let data21 = data.published_at;
      if (typeof data21 === "string") {
        if (!formats4.validate(data21)) {
          const err63 = {
            instancePath: instancePath + "/published_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err63];
          } else {
            vErrors.push(err63);
          }
          errors++;
        }
      } else {
        const err64 = {
          instancePath: instancePath + "/published_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err64];
        } else {
          vErrors.push(err64);
        }
        errors++;
      }
    }
    if (data.raw_sha256 !== undefined) {
      let data22 = data.raw_sha256;
      if (typeof data22 === "string") {
        if (!pattern10.test(data22)) {
          const err65 = {
            instancePath: instancePath + "/raw_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err65];
          } else {
            vErrors.push(err65);
          }
          errors++;
        }
      } else {
        const err66 = {
          instancePath: instancePath + "/raw_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err66];
        } else {
          vErrors.push(err66);
        }
        errors++;
      }
    }
    if (data.record_count !== undefined) {
      let data23 = data.record_count;
      if (!(typeof data23 == "number" && !(data23 % 1) && !isNaN(data23) && isFinite(data23))) {
        const err67 = {
          instancePath: instancePath + "/record_count",
          schemaPath: "#/properties/record_count/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err67];
        } else {
          vErrors.push(err67);
        }
        errors++;
      }
      if (typeof data23 == "number" && isFinite(data23)) {
        if (data23 > 4096 || isNaN(data23)) {
          const err68 = {
            instancePath: instancePath + "/record_count",
            schemaPath: "#/properties/record_count/maximum",
            keyword: "maximum",
            params: { comparison: "<=", limit: 4096 },
            message: "must be <= 4096",
          };
          if (vErrors === null) {
            vErrors = [err68];
          } else {
            vErrors.push(err68);
          }
          errors++;
        }
        if (data23 < 1 || isNaN(data23)) {
          const err69 = {
            instancePath: instancePath + "/record_count",
            schemaPath: "#/properties/record_count/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 1 },
            message: "must be >= 1",
          };
          if (vErrors === null) {
            vErrors = [err69];
          } else {
            vErrors.push(err69);
          }
          errors++;
        }
      }
    }
    if (data.retrieved_at !== undefined) {
      let data24 = data.retrieved_at;
      if (typeof data24 === "string") {
        if (!formats4.validate(data24)) {
          const err70 = {
            instancePath: instancePath + "/retrieved_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err70];
          } else {
            vErrors.push(err70);
          }
          errors++;
        }
      } else {
        const err71 = {
          instancePath: instancePath + "/retrieved_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err71];
        } else {
          vErrors.push(err71);
        }
        errors++;
      }
    }
  } else {
    const err72 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err72];
    } else {
      vErrors.push(err72);
    }
    errors++;
  }
  validate68.errors = vErrors;
  return errors === 0;
}
validate68.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate67(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate67.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.content_sha === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "content_sha" },
        message: "must have required property '" + "content_sha" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.pack_sha256 === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "pack_sha256" },
        message: "must have required property '" + "pack_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.metadata === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "metadata" },
        message: "must have required property '" + "metadata" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.approved_at === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "approved_at" },
        message: "must have required property '" + "approved_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.approval_key_id === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "approval_key_id" },
        message: "must have required property '" + "approval_key_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.policy_sha256 === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "policy_sha256" },
        message: "must have required property '" + "policy_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.evaluation_at === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evaluation_at" },
        message: "must have required property '" + "evaluation_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.valid_from === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "valid_from" },
        message: "must have required property '" + "valid_from" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    if (data.expires_at === undefined) {
      const err8 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "expires_at" },
        message: "must have required property '" + "expires_at" + "'",
      };
      if (vErrors === null) {
        vErrors = [err8];
      } else {
        vErrors.push(err8);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema98.properties, key0)) {
        const err9 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.approval_key_id !== undefined) {
      let data0 = data.approval_key_id;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (typeof data0 !== "string") {
        const err10 = {
          instancePath: instancePath + "/approval_key_id",
          schemaPath: "#/properties/approval_key_id/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs6 = errors;
      if (data0 !== null) {
        const err11 = {
          instancePath: instancePath + "/approval_key_id",
          schemaPath: "#/properties/approval_key_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid0 = _errs6 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err12 = {
          instancePath: instancePath + "/approval_key_id",
          schemaPath: "#/properties/approval_key_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.approved_at !== undefined) {
      let data1 = data.approved_at;
      const _errs9 = errors;
      let valid2 = false;
      const _errs10 = errors;
      if (typeof data1 === "string") {
        if (!formats4.validate(data1)) {
          const err13 = {
            instancePath: instancePath + "/approved_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/approved_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
      var _valid1 = _errs10 === errors;
      valid2 = valid2 || _valid1;
      const _errs13 = errors;
      if (data1 !== null) {
        const err15 = {
          instancePath: instancePath + "/approved_at",
          schemaPath: "#/properties/approved_at/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
      var _valid1 = _errs13 === errors;
      valid2 = valid2 || _valid1;
      if (!valid2) {
        const err16 = {
          instancePath: instancePath + "/approved_at",
          schemaPath: "#/properties/approved_at/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      } else {
        errors = _errs9;
        if (vErrors !== null) {
          if (_errs9) {
            vErrors.length = _errs9;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.content_sha !== undefined) {
      let data2 = data.content_sha;
      if (typeof data2 === "string") {
        if (!pattern8.test(data2)) {
          const err17 = {
            instancePath: instancePath + "/content_sha",
            schemaPath: "#/$defs/GitSHA40/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{40}$" },
            message: 'must match pattern "' + "^[0-9a-f]{40}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/content_sha",
          schemaPath: "#/$defs/GitSHA40/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
    if (data.evaluation_at !== undefined) {
      let data3 = data.evaluation_at;
      if (typeof data3 === "string") {
        if (!formats4.validate(data3)) {
          const err19 = {
            instancePath: instancePath + "/evaluation_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
      } else {
        const err20 = {
          instancePath: instancePath + "/evaluation_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
    if (data.expires_at !== undefined) {
      let data4 = data.expires_at;
      const _errs22 = errors;
      let valid6 = false;
      const _errs23 = errors;
      if (typeof data4 === "string") {
        if (!formats4.validate(data4)) {
          const err21 = {
            instancePath: instancePath + "/expires_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
        }
      } else {
        const err22 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
      var _valid2 = _errs23 === errors;
      valid6 = valid6 || _valid2;
      const _errs26 = errors;
      if (data4 !== null) {
        const err23 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/properties/expires_at/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err23];
        } else {
          vErrors.push(err23);
        }
        errors++;
      }
      var _valid2 = _errs26 === errors;
      valid6 = valid6 || _valid2;
      if (!valid6) {
        const err24 = {
          instancePath: instancePath + "/expires_at",
          schemaPath: "#/properties/expires_at/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err24];
        } else {
          vErrors.push(err24);
        }
        errors++;
      } else {
        errors = _errs22;
        if (vErrors !== null) {
          if (_errs22) {
            vErrors.length = _errs22;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.metadata !== undefined) {
      let data5 = data.metadata;
      const _errs29 = errors;
      let valid8 = false;
      const _errs30 = errors;
      if (
        !validate68(data5, {
          instancePath: instancePath + "/metadata",
          parentData: data,
          parentDataProperty: "metadata",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
        errors = vErrors.length;
      }
      var _valid3 = _errs30 === errors;
      valid8 = valid8 || _valid3;
      const _errs31 = errors;
      if (data5 !== null) {
        const err25 = {
          instancePath: instancePath + "/metadata",
          schemaPath: "#/properties/metadata/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err25];
        } else {
          vErrors.push(err25);
        }
        errors++;
      }
      var _valid3 = _errs31 === errors;
      valid8 = valid8 || _valid3;
      if (!valid8) {
        const err26 = {
          instancePath: instancePath + "/metadata",
          schemaPath: "#/properties/metadata/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err26];
        } else {
          vErrors.push(err26);
        }
        errors++;
      } else {
        errors = _errs29;
        if (vErrors !== null) {
          if (_errs29) {
            vErrors.length = _errs29;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.pack_sha256 !== undefined) {
      let data6 = data.pack_sha256;
      if (typeof data6 === "string") {
        if (!pattern10.test(data6)) {
          const err27 = {
            instancePath: instancePath + "/pack_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err27];
          } else {
            vErrors.push(err27);
          }
          errors++;
        }
      } else {
        const err28 = {
          instancePath: instancePath + "/pack_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err28];
        } else {
          vErrors.push(err28);
        }
        errors++;
      }
    }
    if (data.policy_sha256 !== undefined) {
      let data7 = data.policy_sha256;
      if (typeof data7 === "string") {
        if (!pattern10.test(data7)) {
          const err29 = {
            instancePath: instancePath + "/policy_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err29];
          } else {
            vErrors.push(err29);
          }
          errors++;
        }
      } else {
        const err30 = {
          instancePath: instancePath + "/policy_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err30];
        } else {
          vErrors.push(err30);
        }
        errors++;
      }
    }
    if (data.valid_from !== undefined) {
      let data8 = data.valid_from;
      const _errs40 = errors;
      let valid11 = false;
      const _errs41 = errors;
      if (typeof data8 === "string") {
        if (!formats4.validate(data8)) {
          const err31 = {
            instancePath: instancePath + "/valid_from",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err31];
          } else {
            vErrors.push(err31);
          }
          errors++;
        }
      } else {
        const err32 = {
          instancePath: instancePath + "/valid_from",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err32];
        } else {
          vErrors.push(err32);
        }
        errors++;
      }
      var _valid4 = _errs41 === errors;
      valid11 = valid11 || _valid4;
      const _errs44 = errors;
      if (data8 !== null) {
        const err33 = {
          instancePath: instancePath + "/valid_from",
          schemaPath: "#/properties/valid_from/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err33];
        } else {
          vErrors.push(err33);
        }
        errors++;
      }
      var _valid4 = _errs44 === errors;
      valid11 = valid11 || _valid4;
      if (!valid11) {
        const err34 = {
          instancePath: instancePath + "/valid_from",
          schemaPath: "#/properties/valid_from/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err34];
        } else {
          vErrors.push(err34);
        }
        errors++;
      } else {
        errors = _errs40;
        if (vErrors !== null) {
          if (_errs40) {
            vErrors.length = _errs40;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err35 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err35];
    } else {
      vErrors.push(err35);
    }
    errors++;
  }
  validate67.errors = vErrors;
  return errors === 0;
}
validate67.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate66(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate66.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.role === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "role" },
        message: "must have required property '" + "role" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "kev_use" ||
          key0 === "member_index" ||
          key0 === "page_evidence_id" ||
          key0 === "parent_evidence_id" ||
          key0 === "role"
        )
      ) {
        const err1 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err1];
        } else {
          vErrors.push(err1);
        }
        errors++;
      }
    }
    if (data.kev_use !== undefined) {
      let data0 = data.kev_use;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (
        !validate67(data0, {
          instancePath: instancePath + "/kev_use",
          parentData: data,
          parentDataProperty: "kev_use",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate67.errors : vErrors.concat(validate67.errors);
        errors = vErrors.length;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs5 = errors;
      if (data0 !== null) {
        const err2 = {
          instancePath: instancePath + "/kev_use",
          schemaPath: "#/properties/kev_use/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
      var _valid0 = _errs5 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err3 = {
          instancePath: instancePath + "/kev_use",
          schemaPath: "#/properties/kev_use/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.member_index !== undefined) {
      let data1 = data.member_index;
      const _errs8 = errors;
      let valid2 = false;
      const _errs9 = errors;
      if (!(typeof data1 == "number" && !(data1 % 1) && !isNaN(data1) && isFinite(data1))) {
        const err4 = {
          instancePath: instancePath + "/member_index",
          schemaPath: "#/properties/member_index/anyOf/0/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (typeof data1 == "number" && isFinite(data1)) {
        if (data1 > 63 || isNaN(data1)) {
          const err5 = {
            instancePath: instancePath + "/member_index",
            schemaPath: "#/properties/member_index/anyOf/0/maximum",
            keyword: "maximum",
            params: { comparison: "<=", limit: 63 },
            message: "must be <= 63",
          };
          if (vErrors === null) {
            vErrors = [err5];
          } else {
            vErrors.push(err5);
          }
          errors++;
        }
        if (data1 < 0 || isNaN(data1)) {
          const err6 = {
            instancePath: instancePath + "/member_index",
            schemaPath: "#/properties/member_index/anyOf/0/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
      }
      var _valid1 = _errs9 === errors;
      valid2 = valid2 || _valid1;
      const _errs11 = errors;
      if (data1 !== null) {
        const err7 = {
          instancePath: instancePath + "/member_index",
          schemaPath: "#/properties/member_index/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
      var _valid1 = _errs11 === errors;
      valid2 = valid2 || _valid1;
      if (!valid2) {
        const err8 = {
          instancePath: instancePath + "/member_index",
          schemaPath: "#/properties/member_index/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      } else {
        errors = _errs8;
        if (vErrors !== null) {
          if (_errs8) {
            vErrors.length = _errs8;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.page_evidence_id !== undefined) {
      let data2 = data.page_evidence_id;
      const _errs14 = errors;
      let valid3 = false;
      const _errs15 = errors;
      if (typeof data2 === "string") {
        if (!pattern5.test(data2)) {
          const err9 = {
            instancePath: instancePath + "/page_evidence_id",
            schemaPath: "#/$defs/EvidenceId/pattern",
            keyword: "pattern",
            params: { pattern: "^ev1_[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/page_evidence_id",
          schemaPath: "#/$defs/EvidenceId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      var _valid2 = _errs15 === errors;
      valid3 = valid3 || _valid2;
      const _errs18 = errors;
      if (data2 !== null) {
        const err11 = {
          instancePath: instancePath + "/page_evidence_id",
          schemaPath: "#/properties/page_evidence_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid2 = _errs18 === errors;
      valid3 = valid3 || _valid2;
      if (!valid3) {
        const err12 = {
          instancePath: instancePath + "/page_evidence_id",
          schemaPath: "#/properties/page_evidence_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      } else {
        errors = _errs14;
        if (vErrors !== null) {
          if (_errs14) {
            vErrors.length = _errs14;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.parent_evidence_id !== undefined) {
      let data3 = data.parent_evidence_id;
      const _errs21 = errors;
      let valid5 = false;
      const _errs22 = errors;
      if (typeof data3 === "string") {
        if (!pattern5.test(data3)) {
          const err13 = {
            instancePath: instancePath + "/parent_evidence_id",
            schemaPath: "#/$defs/EvidenceId/pattern",
            keyword: "pattern",
            params: { pattern: "^ev1_[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/parent_evidence_id",
          schemaPath: "#/$defs/EvidenceId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
      var _valid3 = _errs22 === errors;
      valid5 = valid5 || _valid3;
      const _errs25 = errors;
      if (data3 !== null) {
        const err15 = {
          instancePath: instancePath + "/parent_evidence_id",
          schemaPath: "#/properties/parent_evidence_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
      var _valid3 = _errs25 === errors;
      valid5 = valid5 || _valid3;
      if (!valid5) {
        const err16 = {
          instancePath: instancePath + "/parent_evidence_id",
          schemaPath: "#/properties/parent_evidence_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      } else {
        errors = _errs21;
        if (vErrors !== null) {
          if (_errs21) {
            vErrors.length = _errs21;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.role !== undefined) {
      let data4 = data.role;
      if (typeof data4 !== "string") {
        const err17 = {
          instancePath: instancePath + "/role",
          schemaPath: "#/properties/role/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
      if (!(data4 === "page" || data4 === "subject")) {
        const err18 = {
          instancePath: instancePath + "/role",
          schemaPath: "#/properties/role/enum",
          keyword: "enum",
          params: { allowedValues: schema97.properties.role.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
  } else {
    const err19 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err19];
    } else {
      vErrors.push(err19);
    }
    errors++;
  }
  validate66.errors = vErrors;
  return errors === 0;
}
validate66.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate53(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate53.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  const _errs0 = errors;
  let valid0 = false;
  const _errs1 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.index_alias === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/$defs/EvidenceSourceRow/required",
        keyword: "required",
        params: { missingProperty: "index_alias" },
        message: "must have required property '" + "index_alias" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.record_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/$defs/EvidenceSourceRow/required",
        keyword: "required",
        params: { missingProperty: "record_id" },
        message: "must have required property '" + "record_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "index_alias" || key0 === "record_id")) {
        const err2 = {
          instancePath,
          schemaPath: "#/$defs/EvidenceSourceRow/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.index_alias !== undefined) {
      if (typeof data.index_alias !== "string") {
        const err3 = {
          instancePath: instancePath + "/index_alias",
          schemaPath: "#/$defs/EvidenceSourceRow/properties/index_alias/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.record_id !== undefined) {
      if (typeof data.record_id !== "string") {
        const err4 = {
          instancePath: instancePath + "/record_id",
          schemaPath: "#/$defs/EvidenceSourceRow/properties/record_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
  } else {
    const err5 = {
      instancePath,
      schemaPath: "#/$defs/EvidenceSourceRow/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err5];
    } else {
      vErrors.push(err5);
    }
    errors++;
  }
  var _valid0 = _errs1 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    var props0 = true;
  }
  const _errs9 = errors;
  if (
    !validate54(data, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors })
  ) {
    vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
    errors = vErrors.length;
  }
  var _valid0 = _errs9 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    if (props0 !== true) {
      props0 = true;
    }
  }
  const _errs10 = errors;
  if (
    !validate56(data, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors })
  ) {
    vErrors = vErrors === null ? validate56.errors : vErrors.concat(validate56.errors);
    errors = vErrors.length;
  }
  var _valid0 = _errs10 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    if (props0 !== true) {
      props0 = true;
    }
  }
  const _errs11 = errors;
  if (
    !validate61(data, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors })
  ) {
    vErrors = vErrors === null ? validate61.errors : vErrors.concat(validate61.errors);
    errors = vErrors.length;
  }
  var _valid0 = _errs11 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    if (props0 !== true) {
      props0 = true;
    }
  }
  const _errs12 = errors;
  if (
    !validate64(data, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors })
  ) {
    vErrors = vErrors === null ? validate64.errors : vErrors.concat(validate64.errors);
    errors = vErrors.length;
  }
  var _valid0 = _errs12 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    if (props0 !== true) {
      props0 = true;
    }
  }
  const _errs13 = errors;
  if (
    !validate66(data, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors })
  ) {
    vErrors = vErrors === null ? validate66.errors : vErrors.concat(validate66.errors);
    errors = vErrors.length;
  }
  var _valid0 = _errs13 === errors;
  valid0 = valid0 || _valid0;
  if (_valid0) {
    if (props0 !== true) {
      props0 = true;
    }
  }
  if (!valid0) {
    const err6 = {
      instancePath,
      schemaPath: "#/anyOf",
      keyword: "anyOf",
      params: {},
      message: "must match a schema in anyOf",
    };
    if (vErrors === null) {
      vErrors = [err6];
    } else {
      vErrors.push(err6);
    }
    errors++;
  } else {
    errors = _errs0;
    if (vErrors !== null) {
      if (_errs0) {
        vErrors.length = _errs0;
      } else {
        vErrors = null;
      }
    }
  }
  validate53.errors = vErrors;
  evaluated0.props = props0;
  return errors === 0;
}
validate53.evaluated = { dynamicProps: true, dynamicItems: false };
const schema115 = {
  additionalProperties: { $ref: "#/$defs/EvidenceValue" },
  propertyNames: {
    enum: [
      "timestamp",
      "agent.id",
      "agent.name",
      "rule.id",
      "rule.level",
      "rule.groups",
      "data.srcip",
      "data.dstip",
      "vulnerability.id",
      "vulnerability.severity",
      "vulnerability.detected_at",
      "package.name",
      "package.version",
      "count",
      "outcome",
      "matched_nothing",
      "relation",
      "approximate",
      "bucket_key",
      "operand_ids",
      "expectation_id",
      "expectation_version",
      "kev_cve",
      "kev_lookup",
      "kev_freshness",
      "kev_added_on",
      "kev_coverage",
      "kev_reason",
      "kev_row_n",
      "kev_subject_n",
      "kev_annotated_n",
      "kev_omitted_n",
      "kev_hit_n",
      "kev_not_listed_n",
      "kev_invalid_n",
      "kev_unavailable_n",
      "kev_fresh_n",
      "kev_stale_n",
      "kev_not_yet_valid_n",
      "kev_unknown_n",
    ],
  },
  type: "object",
};
const schema116 = {
  anyOf: [
    { type: "string" },
    { type: "integer" },
    { type: "boolean" },
    { items: { type: "string" }, type: "array" },
    { type: "null" },
  ],
};
function validate74(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate74.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    for (const key0 in data) {
      const _errs1 = errors;
      if (
        !(
          key0 === "timestamp" ||
          key0 === "agent.id" ||
          key0 === "agent.name" ||
          key0 === "rule.id" ||
          key0 === "rule.level" ||
          key0 === "rule.groups" ||
          key0 === "data.srcip" ||
          key0 === "data.dstip" ||
          key0 === "vulnerability.id" ||
          key0 === "vulnerability.severity" ||
          key0 === "vulnerability.detected_at" ||
          key0 === "package.name" ||
          key0 === "package.version" ||
          key0 === "count" ||
          key0 === "outcome" ||
          key0 === "matched_nothing" ||
          key0 === "relation" ||
          key0 === "approximate" ||
          key0 === "bucket_key" ||
          key0 === "operand_ids" ||
          key0 === "expectation_id" ||
          key0 === "expectation_version" ||
          key0 === "kev_cve" ||
          key0 === "kev_lookup" ||
          key0 === "kev_freshness" ||
          key0 === "kev_added_on" ||
          key0 === "kev_coverage" ||
          key0 === "kev_reason" ||
          key0 === "kev_row_n" ||
          key0 === "kev_subject_n" ||
          key0 === "kev_annotated_n" ||
          key0 === "kev_omitted_n" ||
          key0 === "kev_hit_n" ||
          key0 === "kev_not_listed_n" ||
          key0 === "kev_invalid_n" ||
          key0 === "kev_unavailable_n" ||
          key0 === "kev_fresh_n" ||
          key0 === "kev_stale_n" ||
          key0 === "kev_not_yet_valid_n" ||
          key0 === "kev_unknown_n"
        )
      ) {
        const err0 = {
          instancePath,
          schemaPath: "#/propertyNames/enum",
          keyword: "enum",
          params: { allowedValues: schema115.propertyNames.enum },
          message: "must be equal to one of the allowed values",
          propertyName: key0,
        };
        if (vErrors === null) {
          vErrors = [err0];
        } else {
          vErrors.push(err0);
        }
        errors++;
      }
      var valid0 = _errs1 === errors;
      if (!valid0) {
        const err1 = {
          instancePath,
          schemaPath: "#/propertyNames",
          keyword: "propertyNames",
          params: { propertyName: key0 },
          message: "property name must be valid",
        };
        if (vErrors === null) {
          vErrors = [err1];
        } else {
          vErrors.push(err1);
        }
        errors++;
      }
    }
    for (const key1 in data) {
      let data0 = data[key1];
      const _errs5 = errors;
      let valid3 = false;
      const _errs6 = errors;
      if (typeof data0 !== "string") {
        const err2 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
      var _valid0 = _errs6 === errors;
      valid3 = valid3 || _valid0;
      const _errs8 = errors;
      if (!(typeof data0 == "number" && !(data0 % 1) && !isNaN(data0) && isFinite(data0))) {
        const err3 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf/1/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
      var _valid0 = _errs8 === errors;
      valid3 = valid3 || _valid0;
      const _errs10 = errors;
      if (typeof data0 !== "boolean") {
        const err4 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf/2/type",
          keyword: "type",
          params: { type: "boolean" },
          message: "must be boolean",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      var _valid0 = _errs10 === errors;
      valid3 = valid3 || _valid0;
      const _errs12 = errors;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (typeof data0[i0] !== "string") {
            const err5 = {
              instancePath:
                instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1") + "/" + i0,
              schemaPath: "#/$defs/EvidenceValue/anyOf/3/items/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err5];
            } else {
              vErrors.push(err5);
            }
            errors++;
          }
        }
      } else {
        const err6 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf/3/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      var _valid0 = _errs12 === errors;
      valid3 = valid3 || _valid0;
      const _errs16 = errors;
      if (data0 !== null) {
        const err7 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf/4/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
      var _valid0 = _errs16 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err8 = {
          instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
          schemaPath: "#/$defs/EvidenceValue/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      } else {
        errors = _errs5;
        if (vErrors !== null) {
          if (_errs5) {
            vErrors.length = _errs5;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err9 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err9];
    } else {
      vErrors.push(err9);
    }
    errors++;
  }
  validate74.errors = vErrors;
  return errors === 0;
}
validate74.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate50(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate50.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.evidence_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evidence_id" },
        message: "must have required property '" + "evidence_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.topic_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.kind === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "kind" },
        message: "must have required property '" + "kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.source === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "source" },
        message: "must have required property '" + "source" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.snapshot === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "snapshot" },
        message: "must have required property '" + "snapshot" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.values === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "values" },
        message: "must have required property '" + "values" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.visibility === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "visibility" },
        message: "must have required property '" + "visibility" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.scope_hash === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "scope_hash" },
        message: "must have required property '" + "scope_hash" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema72.properties, key0)) {
        const err8 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.check_id !== undefined) {
      let data0 = data.check_id;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (typeof data0 === "string") {
        if (!pattern4.test(data0)) {
          const err9 = {
            instancePath: instancePath + "/check_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/check_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs7 = errors;
      if (data0 !== null) {
        const err11 = {
          instancePath: instancePath + "/check_id",
          schemaPath: "#/properties/check_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid0 = _errs7 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err12 = {
          instancePath: instancePath + "/check_id",
          schemaPath: "#/properties/check_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.evidence_id !== undefined) {
      let data1 = data.evidence_id;
      if (typeof data1 === "string") {
        if (!pattern5.test(data1)) {
          const err13 = {
            instancePath: instancePath + "/evidence_id",
            schemaPath: "#/$defs/EvidenceId/pattern",
            keyword: "pattern",
            params: { pattern: "^ev1_[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/evidence_id",
          schemaPath: "#/$defs/EvidenceId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.fetch_id !== undefined) {
      let data2 = data.fetch_id;
      const _errs13 = errors;
      let valid4 = false;
      const _errs14 = errors;
      if (typeof data2 === "string") {
        if (!pattern4.test(data2)) {
          const err15 = {
            instancePath: instancePath + "/fetch_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err15];
          } else {
            vErrors.push(err15);
          }
          errors++;
        }
      } else {
        const err16 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
      var _valid1 = _errs14 === errors;
      valid4 = valid4 || _valid1;
      const _errs17 = errors;
      if (data2 !== null) {
        const err17 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/properties/fetch_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err17];
        } else {
          vErrors.push(err17);
        }
        errors++;
      }
      var _valid1 = _errs17 === errors;
      valid4 = valid4 || _valid1;
      if (!valid4) {
        const err18 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/properties/fetch_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      } else {
        errors = _errs13;
        if (vErrors !== null) {
          if (_errs13) {
            vErrors.length = _errs13;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.kind !== undefined) {
      let data3 = data.kind;
      if (typeof data3 !== "string") {
        const err19 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
      if (!(data3 === "row" || data3 === "aggregate" || data3 === "check" || data3 === "context")) {
        const err20 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/enum",
          keyword: "enum",
          params: { allowedValues: schema72.properties.kind.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
    if (data.scope_hash !== undefined) {
      let data4 = data.scope_hash;
      if (typeof data4 === "string") {
        if (!pattern10.test(data4)) {
          const err21 = {
            instancePath: instancePath + "/scope_hash",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
        }
      } else {
        const err22 = {
          instancePath: instancePath + "/scope_hash",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
    }
    if (data.snapshot !== undefined) {
      if (
        !validate51(data.snapshot, {
          instancePath: instancePath + "/snapshot",
          parentData: data,
          parentDataProperty: "snapshot",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate51.errors : vErrors.concat(validate51.errors);
        errors = vErrors.length;
      }
    }
    if (data.source !== undefined) {
      if (
        !validate53(data.source, {
          instancePath: instancePath + "/source",
          parentData: data,
          parentDataProperty: "source",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate53.errors : vErrors.concat(validate53.errors);
        errors = vErrors.length;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
    if (data.values !== undefined) {
      let data8 = data.values;
      if (
        !validate74(data8, {
          instancePath: instancePath + "/values",
          parentData: data,
          parentDataProperty: "values",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate74.errors : vErrors.concat(validate74.errors);
        errors = vErrors.length;
      }
      if (data8 && typeof data8 == "object" && !Array.isArray(data8)) {
        for (const key1 in data8) {
          let data9 = data8[key1];
          const _errs31 = errors;
          let valid8 = false;
          const _errs32 = errors;
          if (typeof data9 !== "string") {
            const err23 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf/0/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err23];
            } else {
              vErrors.push(err23);
            }
            errors++;
          }
          var _valid2 = _errs32 === errors;
          valid8 = valid8 || _valid2;
          const _errs34 = errors;
          if (!(typeof data9 == "number" && !(data9 % 1) && !isNaN(data9) && isFinite(data9))) {
            const err24 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf/1/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
          }
          var _valid2 = _errs34 === errors;
          valid8 = valid8 || _valid2;
          const _errs36 = errors;
          if (typeof data9 !== "boolean") {
            const err25 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf/2/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err25];
            } else {
              vErrors.push(err25);
            }
            errors++;
          }
          var _valid2 = _errs36 === errors;
          valid8 = valid8 || _valid2;
          const _errs38 = errors;
          if (data9 !== null) {
            const err26 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf/3/type",
              keyword: "type",
              params: { type: "null" },
              message: "must be null",
            };
            if (vErrors === null) {
              vErrors = [err26];
            } else {
              vErrors.push(err26);
            }
            errors++;
          }
          var _valid2 = _errs38 === errors;
          valid8 = valid8 || _valid2;
          const _errs40 = errors;
          if (Array.isArray(data9)) {
            const len0 = data9.length;
            for (let i0 = 0; i0 < len0; i0++) {
              if (typeof data9[i0] !== "string") {
                const err27 = {
                  instancePath:
                    instancePath +
                    "/values/" +
                    key1.replace(/~/g, "~0").replace(/\//g, "~1") +
                    "/" +
                    i0,
                  schemaPath: "#/properties/values/additionalProperties/anyOf/4/items/type",
                  keyword: "type",
                  params: { type: "string" },
                  message: "must be string",
                };
                if (vErrors === null) {
                  vErrors = [err27];
                } else {
                  vErrors.push(err27);
                }
                errors++;
              }
            }
          } else {
            const err28 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf/4/type",
              keyword: "type",
              params: { type: "array" },
              message: "must be array",
            };
            if (vErrors === null) {
              vErrors = [err28];
            } else {
              vErrors.push(err28);
            }
            errors++;
          }
          var _valid2 = _errs40 === errors;
          valid8 = valid8 || _valid2;
          if (!valid8) {
            const err29 = {
              instancePath:
                instancePath + "/values/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/values/additionalProperties/anyOf",
              keyword: "anyOf",
              params: {},
              message: "must match a schema in anyOf",
            };
            if (vErrors === null) {
              vErrors = [err29];
            } else {
              vErrors.push(err29);
            }
            errors++;
          } else {
            errors = _errs31;
            if (vErrors !== null) {
              if (_errs31) {
                vErrors.length = _errs31;
              } else {
                vErrors = null;
              }
            }
          }
        }
      } else {
        const err30 = {
          instancePath: instancePath + "/values",
          schemaPath: "#/properties/values/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err30];
        } else {
          vErrors.push(err30);
        }
        errors++;
      }
    }
    if (data.visibility !== undefined) {
      let data11 = data.visibility;
      if (typeof data11 !== "string") {
        const err31 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err31];
        } else {
          vErrors.push(err31);
        }
        errors++;
      }
      if (!(data11 === "full" || data11 === "filtered" || data11 === "unknown")) {
        const err32 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/enum",
          keyword: "enum",
          params: { allowedValues: schema117.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err32];
        } else {
          vErrors.push(err32);
        }
        errors++;
      }
    }
  } else {
    const err33 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err33];
    } else {
      vErrors.push(err33);
    }
    errors++;
  }
  validate50.errors = vErrors;
  return errors === 0;
}
validate50.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate45(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate45.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.index_exists === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "index_exists" },
        message: "must have required property '" + "index_exists" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.window_has_data === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "window_has_data" },
        message: "must have required property '" + "window_has_data" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.filter_probes === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "filter_probes" },
        message: "must have required property '" + "filter_probes" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.matched_nothing === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "matched_nothing" },
        message: "must have required property '" + "matched_nothing" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.visibility === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "visibility" },
        message: "must have required property '" + "visibility" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.snapshot === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "snapshot" },
        message: "must have required property '" + "snapshot" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.consistency === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "consistency" },
        message: "must have required property '" + "consistency" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.items === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "items" },
        message: "must have required property '" + "items" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema66.properties, key0)) {
        const err8 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.combination_zero !== undefined) {
      if (typeof data.combination_zero !== "boolean") {
        const err9 = {
          instancePath: instancePath + "/combination_zero",
          schemaPath: "#/properties/combination_zero/type",
          keyword: "type",
          params: { type: "boolean" },
          message: "must be boolean",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.consistency !== undefined) {
      let data1 = data.consistency;
      if (typeof data1 !== "string") {
        const err10 = {
          instancePath: instancePath + "/consistency",
          schemaPath: "#/properties/consistency/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      if (!(data1 === "coherent" || data1 === "unconfirmed")) {
        const err11 = {
          instancePath: instancePath + "/consistency",
          schemaPath: "#/properties/consistency/enum",
          keyword: "enum",
          params: { allowedValues: schema66.properties.consistency.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.filter_probes !== undefined) {
      let data2 = data.filter_probes;
      if (Array.isArray(data2)) {
        const len0 = data2.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate46(data2[i0], {
              instancePath: instancePath + "/filter_probes/" + i0,
              parentData: data2,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate46.errors : vErrors.concat(validate46.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err12 = {
          instancePath: instancePath + "/filter_probes",
          schemaPath: "#/properties/filter_probes/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.index_exists !== undefined) {
      let data4 = data.index_exists;
      if (typeof data4 !== "string") {
        const err13 = {
          instancePath: instancePath + "/index_exists",
          schemaPath: "#/properties/index_exists/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
      if (!(data4 === "confirmed" || data4 === "unknown")) {
        const err14 = {
          instancePath: instancePath + "/index_exists",
          schemaPath: "#/properties/index_exists/enum",
          keyword: "enum",
          params: { allowedValues: schema66.properties.index_exists.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.items !== undefined) {
      let data5 = data.items;
      if (Array.isArray(data5)) {
        const len1 = data5.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate50(data5[i1], {
              instancePath: instancePath + "/items/" + i1,
              parentData: data5,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate50.errors : vErrors.concat(validate50.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/items",
          schemaPath: "#/properties/items/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.matched_nothing !== undefined) {
      let data7 = data.matched_nothing;
      if (Array.isArray(data7)) {
        const len2 = data7.length;
        for (let i2 = 0; i2 < len2; i2++) {
          let data8 = data7[i2];
          if (typeof data8 !== "string") {
            const err16 = {
              instancePath: instancePath + "/matched_nothing/" + i2,
              schemaPath: "#/$defs/FieldId/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err16];
            } else {
              vErrors.push(err16);
            }
            errors++;
          }
          if (
            !(
              data8 === "timestamp" ||
              data8 === "agent.id" ||
              data8 === "agent.name" ||
              data8 === "rule.id" ||
              data8 === "rule.level" ||
              data8 === "rule.groups" ||
              data8 === "data.srcip" ||
              data8 === "data.dstip" ||
              data8 === "vulnerability.id" ||
              data8 === "vulnerability.severity" ||
              data8 === "vulnerability.detected_at" ||
              data8 === "package.name" ||
              data8 === "package.version"
            )
          ) {
            const err17 = {
              instancePath: instancePath + "/matched_nothing/" + i2,
              schemaPath: "#/$defs/FieldId/enum",
              keyword: "enum",
              params: { allowedValues: schema63.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err17];
            } else {
              vErrors.push(err17);
            }
            errors++;
          }
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/matched_nothing",
          schemaPath: "#/properties/matched_nothing/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
    if (data.snapshot !== undefined) {
      if (
        !validate51(data.snapshot, {
          instancePath: instancePath + "/snapshot",
          parentData: data,
          parentDataProperty: "snapshot",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate51.errors : vErrors.concat(validate51.errors);
        errors = vErrors.length;
      }
    }
    if (data.visibility !== undefined) {
      let data10 = data.visibility;
      if (typeof data10 !== "string") {
        const err19 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
      if (!(data10 === "full" || data10 === "filtered" || data10 === "unknown")) {
        const err20 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/enum",
          keyword: "enum",
          params: { allowedValues: schema117.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
    if (data.window_count !== undefined) {
      let data11 = data.window_count;
      const _errs24 = errors;
      let valid9 = false;
      const _errs25 = errors;
      if (data11 && typeof data11 == "object" && !Array.isArray(data11)) {
        if (data11.value === undefined) {
          const err21 = {
            instancePath: instancePath + "/window_count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "value" },
            message: "must have required property '" + "value" + "'",
          };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
        }
        if (data11.relation === undefined) {
          const err22 = {
            instancePath: instancePath + "/window_count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "relation" },
            message: "must have required property '" + "relation" + "'",
          };
          if (vErrors === null) {
            vErrors = [err22];
          } else {
            vErrors.push(err22);
          }
          errors++;
        }
        if (data11.scope === undefined) {
          const err23 = {
            instancePath: instancePath + "/window_count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "scope" },
            message: "must have required property '" + "scope" + "'",
          };
          if (vErrors === null) {
            vErrors = [err23];
          } else {
            vErrors.push(err23);
          }
          errors++;
        }
        if (data11.computed_by === undefined) {
          const err24 = {
            instancePath: instancePath + "/window_count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "computed_by" },
            message: "must have required property '" + "computed_by" + "'",
          };
          if (vErrors === null) {
            vErrors = [err24];
          } else {
            vErrors.push(err24);
          }
          errors++;
        }
        for (const key1 in data11) {
          if (
            !(
              key1 === "approximate" ||
              key1 === "computed_by" ||
              key1 === "relation" ||
              key1 === "scope" ||
              key1 === "value"
            )
          ) {
            const err25 = {
              instancePath: instancePath + "/window_count",
              schemaPath: "#/$defs/Count/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err25];
            } else {
              vErrors.push(err25);
            }
            errors++;
          }
        }
        if (data11.approximate !== undefined) {
          if (typeof data11.approximate !== "boolean") {
            const err26 = {
              instancePath: instancePath + "/window_count/approximate",
              schemaPath: "#/$defs/Count/properties/approximate/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err26];
            } else {
              vErrors.push(err26);
            }
            errors++;
          }
        }
        if (data11.computed_by !== undefined) {
          let data13 = data11.computed_by;
          if (typeof data13 !== "string") {
            const err27 = {
              instancePath: instancePath + "/window_count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err27];
            } else {
              vErrors.push(err27);
            }
            errors++;
          }
          if ("indexer" !== data13) {
            const err28 = {
              instancePath: instancePath + "/window_count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/const",
              keyword: "const",
              params: { allowedValue: "indexer" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err28];
            } else {
              vErrors.push(err28);
            }
            errors++;
          }
        }
        if (data11.relation !== undefined) {
          let data14 = data11.relation;
          if (typeof data14 !== "string") {
            const err29 = {
              instancePath: instancePath + "/window_count/relation",
              schemaPath: "#/$defs/Count/properties/relation/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err29];
            } else {
              vErrors.push(err29);
            }
            errors++;
          }
          if (!(data14 === "eq" || data14 === "gte")) {
            const err30 = {
              instancePath: instancePath + "/window_count/relation",
              schemaPath: "#/$defs/Count/properties/relation/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.relation.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err30];
            } else {
              vErrors.push(err30);
            }
            errors++;
          }
        }
        if (data11.scope !== undefined) {
          let data15 = data11.scope;
          if (typeof data15 !== "string") {
            const err31 = {
              instancePath: instancePath + "/window_count/scope",
              schemaPath: "#/$defs/Count/properties/scope/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err31];
            } else {
              vErrors.push(err31);
            }
            errors++;
          }
          if (!(data15 === "matching_visible_records" || data15 === "bucket_visible_records")) {
            const err32 = {
              instancePath: instancePath + "/window_count/scope",
              schemaPath: "#/$defs/Count/properties/scope/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.scope.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err32];
            } else {
              vErrors.push(err32);
            }
            errors++;
          }
        }
        if (data11.value !== undefined) {
          let data16 = data11.value;
          if (!(typeof data16 == "number" && !(data16 % 1) && !isNaN(data16) && isFinite(data16))) {
            const err33 = {
              instancePath: instancePath + "/window_count/value",
              schemaPath: "#/$defs/Count/properties/value/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err33];
            } else {
              vErrors.push(err33);
            }
            errors++;
          }
          if (typeof data16 == "number" && isFinite(data16)) {
            if (data16 < 0 || isNaN(data16)) {
              const err34 = {
                instancePath: instancePath + "/window_count/value",
                schemaPath: "#/$defs/Count/properties/value/minimum",
                keyword: "minimum",
                params: { comparison: ">=", limit: 0 },
                message: "must be >= 0",
              };
              if (vErrors === null) {
                vErrors = [err34];
              } else {
                vErrors.push(err34);
              }
              errors++;
            }
          }
        }
      } else {
        const err35 = {
          instancePath: instancePath + "/window_count",
          schemaPath: "#/$defs/Count/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err35];
        } else {
          vErrors.push(err35);
        }
        errors++;
      }
      var _valid0 = _errs25 === errors;
      valid9 = valid9 || _valid0;
      const _errs39 = errors;
      if (data11 !== null) {
        const err36 = {
          instancePath: instancePath + "/window_count",
          schemaPath: "#/properties/window_count/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err36];
        } else {
          vErrors.push(err36);
        }
        errors++;
      }
      var _valid0 = _errs39 === errors;
      valid9 = valid9 || _valid0;
      if (!valid9) {
        const err37 = {
          instancePath: instancePath + "/window_count",
          schemaPath: "#/properties/window_count/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err37];
        } else {
          vErrors.push(err37);
        }
        errors++;
      } else {
        errors = _errs24;
        if (vErrors !== null) {
          if (_errs24) {
            vErrors.length = _errs24;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.window_has_data !== undefined) {
      let data17 = data.window_has_data;
      if (typeof data17 !== "string") {
        const err38 = {
          instancePath: instancePath + "/window_has_data",
          schemaPath: "#/properties/window_has_data/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err38];
        } else {
          vErrors.push(err38);
        }
        errors++;
      }
      if (!(data17 === "confirmed" || data17 === "unknown" || data17 === "empty")) {
        const err39 = {
          instancePath: instancePath + "/window_has_data",
          schemaPath: "#/properties/window_has_data/enum",
          keyword: "enum",
          params: { allowedValues: schema66.properties.window_has_data.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err39];
        } else {
          vErrors.push(err39);
        }
        errors++;
      }
    }
  } else {
    const err40 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err40];
    } else {
      vErrors.push(err40);
    }
    errors++;
  }
  validate45.errors = vErrors;
  return errors === 0;
}
validate45.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema121 = {
  additionalProperties: false,
  properties: {
    code: { $ref: "#/$defs/ErrorCode" },
    details: {
      additionalProperties: {
        anyOf: [
          { type: "string" },
          { type: "integer" },
          { items: { type: "string" }, type: "array" },
        ],
      },
      title: "Details",
      type: "object",
    },
    message: { title: "Message", type: "string" },
    retryable: { title: "Retryable", type: "boolean" },
    trace_id: { title: "Trace Id", type: "string" },
  },
  required: ["code", "message", "retryable", "trace_id"],
  title: "DomainError",
  type: "object",
};
const schema122 = {
  enum: [
    "BAD_REQUEST",
    "UNAUTHENTICATED",
    "AUTH_REQUIRED",
    "AUTH_INVALID",
    "AUTH_EXPIRED",
    "FORBIDDEN",
    "SITE_DENIED",
    "ORIGIN_DENIED",
    "CSRF_DENIED",
    "SCOPE_DENIED",
    "FOLLOWUP_EXPIRED",
    "FOLLOWUP_CONFLICT",
    "QUESTION_ACTIVE",
    "IDEMPOTENCY_CONFLICT",
    "POLICY_CHANGED",
    "CONTENT_CHANGED",
    "BUSY",
    "RATE_LIMITED",
    "UNSUPPORTED_MODEL",
    "UNSUPPORTED_EFFORT",
    "INVALID_WINDOW",
    "INVALID_FILTER",
    "INVALID_SCHEMA",
    "DEPENDENCY_UNAVAILABLE",
    "SERVICE_DISABLED",
    "CONFIG_INVALID",
    "INTERNAL",
    "INDEXER_AUTH_REJECTED",
    "INDEXER_DENIED",
    "INDEXER_UNAVAILABLE",
    "MAPPING_UNSUPPORTED",
    "QUERY_INVALID",
    "CA_UNTRUSTED",
    "TOKEN_BROKER_UNAVAILABLE",
    "CONTEXT_EXCEEDED",
    "TOKEN_COUNT_UNAVAILABLE",
    "BUDGET_EXCEEDED",
    "MODEL_UNAVAILABLE",
    "GUARDRAIL_BLOCKED",
    "INVALID_MODEL_OUTPUT",
    "CONTENT_INVALID",
    "LEASE_LOST",
    "FEEDBACK_UNAVAILABLE",
    "FEEDBACK_INVALID",
    "EVIDENCE_INVALID",
    "EVIDENCE_LIMIT",
    "CAPACITY_LIMIT",
    "DEADLINE_EXCEEDED",
    "AUDIT_UNAVAILABLE",
    "REQUEST_COMPLETED",
    "REQUEST_ABANDONED",
    "INVALID_CONTINUATION",
    "REQUEST_TOO_LARGE",
    "REQUEST_COMPLEXITY",
    "CURSOR_EXPIRED",
    "INVALID_MODEL_SELECTION",
  ],
  title: "ErrorCode",
  type: "string",
};
function validate79(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate79.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.code === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "code" },
        message: "must have required property '" + "code" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.message === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "message" },
        message: "must have required property '" + "message" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.retryable === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "retryable" },
        message: "must have required property '" + "retryable" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.trace_id === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "trace_id" },
        message: "must have required property '" + "trace_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "code" ||
          key0 === "details" ||
          key0 === "message" ||
          key0 === "retryable" ||
          key0 === "trace_id"
        )
      ) {
        const err4 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.code !== undefined) {
      let data0 = data.code;
      if (typeof data0 !== "string") {
        const err5 = {
          instancePath: instancePath + "/code",
          schemaPath: "#/$defs/ErrorCode/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
      if (
        !(
          data0 === "BAD_REQUEST" ||
          data0 === "UNAUTHENTICATED" ||
          data0 === "AUTH_REQUIRED" ||
          data0 === "AUTH_INVALID" ||
          data0 === "AUTH_EXPIRED" ||
          data0 === "FORBIDDEN" ||
          data0 === "SITE_DENIED" ||
          data0 === "ORIGIN_DENIED" ||
          data0 === "CSRF_DENIED" ||
          data0 === "SCOPE_DENIED" ||
          data0 === "FOLLOWUP_EXPIRED" ||
          data0 === "FOLLOWUP_CONFLICT" ||
          data0 === "QUESTION_ACTIVE" ||
          data0 === "IDEMPOTENCY_CONFLICT" ||
          data0 === "POLICY_CHANGED" ||
          data0 === "CONTENT_CHANGED" ||
          data0 === "BUSY" ||
          data0 === "RATE_LIMITED" ||
          data0 === "UNSUPPORTED_MODEL" ||
          data0 === "UNSUPPORTED_EFFORT" ||
          data0 === "INVALID_WINDOW" ||
          data0 === "INVALID_FILTER" ||
          data0 === "INVALID_SCHEMA" ||
          data0 === "DEPENDENCY_UNAVAILABLE" ||
          data0 === "SERVICE_DISABLED" ||
          data0 === "CONFIG_INVALID" ||
          data0 === "INTERNAL" ||
          data0 === "INDEXER_AUTH_REJECTED" ||
          data0 === "INDEXER_DENIED" ||
          data0 === "INDEXER_UNAVAILABLE" ||
          data0 === "MAPPING_UNSUPPORTED" ||
          data0 === "QUERY_INVALID" ||
          data0 === "CA_UNTRUSTED" ||
          data0 === "TOKEN_BROKER_UNAVAILABLE" ||
          data0 === "CONTEXT_EXCEEDED" ||
          data0 === "TOKEN_COUNT_UNAVAILABLE" ||
          data0 === "BUDGET_EXCEEDED" ||
          data0 === "MODEL_UNAVAILABLE" ||
          data0 === "GUARDRAIL_BLOCKED" ||
          data0 === "INVALID_MODEL_OUTPUT" ||
          data0 === "CONTENT_INVALID" ||
          data0 === "LEASE_LOST" ||
          data0 === "FEEDBACK_UNAVAILABLE" ||
          data0 === "FEEDBACK_INVALID" ||
          data0 === "EVIDENCE_INVALID" ||
          data0 === "EVIDENCE_LIMIT" ||
          data0 === "CAPACITY_LIMIT" ||
          data0 === "DEADLINE_EXCEEDED" ||
          data0 === "AUDIT_UNAVAILABLE" ||
          data0 === "REQUEST_COMPLETED" ||
          data0 === "REQUEST_ABANDONED" ||
          data0 === "INVALID_CONTINUATION" ||
          data0 === "REQUEST_TOO_LARGE" ||
          data0 === "REQUEST_COMPLEXITY" ||
          data0 === "CURSOR_EXPIRED" ||
          data0 === "INVALID_MODEL_SELECTION"
        )
      ) {
        const err6 = {
          instancePath: instancePath + "/code",
          schemaPath: "#/$defs/ErrorCode/enum",
          keyword: "enum",
          params: { allowedValues: schema122.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.details !== undefined) {
      let data1 = data.details;
      if (data1 && typeof data1 == "object" && !Array.isArray(data1)) {
        for (const key1 in data1) {
          let data2 = data1[key1];
          const _errs9 = errors;
          let valid3 = false;
          const _errs10 = errors;
          if (typeof data2 !== "string") {
            const err7 = {
              instancePath:
                instancePath + "/details/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/details/additionalProperties/anyOf/0/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err7];
            } else {
              vErrors.push(err7);
            }
            errors++;
          }
          var _valid0 = _errs10 === errors;
          valid3 = valid3 || _valid0;
          const _errs12 = errors;
          if (!(typeof data2 == "number" && !(data2 % 1) && !isNaN(data2) && isFinite(data2))) {
            const err8 = {
              instancePath:
                instancePath + "/details/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/details/additionalProperties/anyOf/1/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err8];
            } else {
              vErrors.push(err8);
            }
            errors++;
          }
          var _valid0 = _errs12 === errors;
          valid3 = valid3 || _valid0;
          const _errs14 = errors;
          if (Array.isArray(data2)) {
            const len0 = data2.length;
            for (let i0 = 0; i0 < len0; i0++) {
              if (typeof data2[i0] !== "string") {
                const err9 = {
                  instancePath:
                    instancePath +
                    "/details/" +
                    key1.replace(/~/g, "~0").replace(/\//g, "~1") +
                    "/" +
                    i0,
                  schemaPath: "#/properties/details/additionalProperties/anyOf/2/items/type",
                  keyword: "type",
                  params: { type: "string" },
                  message: "must be string",
                };
                if (vErrors === null) {
                  vErrors = [err9];
                } else {
                  vErrors.push(err9);
                }
                errors++;
              }
            }
          } else {
            const err10 = {
              instancePath:
                instancePath + "/details/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/details/additionalProperties/anyOf/2/type",
              keyword: "type",
              params: { type: "array" },
              message: "must be array",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
          var _valid0 = _errs14 === errors;
          valid3 = valid3 || _valid0;
          if (!valid3) {
            const err11 = {
              instancePath:
                instancePath + "/details/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/properties/details/additionalProperties/anyOf",
              keyword: "anyOf",
              params: {},
              message: "must match a schema in anyOf",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          } else {
            errors = _errs9;
            if (vErrors !== null) {
              if (_errs9) {
                vErrors.length = _errs9;
              } else {
                vErrors = null;
              }
            }
          }
        }
      } else {
        const err12 = {
          instancePath: instancePath + "/details",
          schemaPath: "#/properties/details/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.message !== undefined) {
      if (typeof data.message !== "string") {
        const err13 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
    if (data.retryable !== undefined) {
      if (typeof data.retryable !== "boolean") {
        const err14 = {
          instancePath: instancePath + "/retryable",
          schemaPath: "#/properties/retryable/type",
          keyword: "type",
          params: { type: "boolean" },
          message: "must be boolean",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.trace_id !== undefined) {
      if (typeof data.trace_id !== "string") {
        const err15 = {
          instancePath: instancePath + "/trace_id",
          schemaPath: "#/properties/trace_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
  } else {
    const err16 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err16];
    } else {
      vErrors.push(err16);
    }
    errors++;
  }
  validate79.errors = vErrors;
  return errors === 0;
}
validate79.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema124 = {
  additionalProperties: false,
  properties: {
    evidence_id: { $ref: "#/$defs/EvidenceId" },
    fetch_id: { $ref: "#/$defs/ContentId" },
    record_ref: { anyOf: [{ $ref: "#/$defs/RecordRef" }, { type: "null" }], default: null },
    topic_id: { $ref: "#/$defs/TopicId" },
    values: {
      additionalProperties: { $ref: "#/$defs/EvidenceValue" },
      propertyNames: { $ref: "#/$defs/FieldId" },
      title: "Values",
      type: "object",
    },
  },
  required: ["evidence_id", "topic_id", "fetch_id", "values"],
  title: "EvidenceRow",
  type: "object",
};
const schema127 = {
  additionalProperties: false,
  properties: {
    index_alias: { title: "Index Alias", type: "string" },
    record_id: { title: "Record Id", type: "string" },
  },
  required: ["index_alias", "record_id"],
  title: "RecordRef",
  type: "object",
};
function validate82(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate82.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.evidence_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "evidence_id" },
        message: "must have required property '" + "evidence_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.topic_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.fetch_id === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "fetch_id" },
        message: "must have required property '" + "fetch_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.values === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "values" },
        message: "must have required property '" + "values" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "evidence_id" ||
          key0 === "fetch_id" ||
          key0 === "record_ref" ||
          key0 === "topic_id" ||
          key0 === "values"
        )
      ) {
        const err4 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.evidence_id !== undefined) {
      let data0 = data.evidence_id;
      if (typeof data0 === "string") {
        if (!pattern5.test(data0)) {
          const err5 = {
            instancePath: instancePath + "/evidence_id",
            schemaPath: "#/$defs/EvidenceId/pattern",
            keyword: "pattern",
            params: { pattern: "^ev1_[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^ev1_[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err5];
          } else {
            vErrors.push(err5);
          }
          errors++;
        }
      } else {
        const err6 = {
          instancePath: instancePath + "/evidence_id",
          schemaPath: "#/$defs/EvidenceId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.fetch_id !== undefined) {
      let data1 = data.fetch_id;
      if (typeof data1 === "string") {
        if (!pattern4.test(data1)) {
          const err7 = {
            instancePath: instancePath + "/fetch_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      } else {
        const err8 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.record_ref !== undefined) {
      let data2 = data.record_ref;
      const _errs9 = errors;
      let valid3 = false;
      const _errs10 = errors;
      if (data2 && typeof data2 == "object" && !Array.isArray(data2)) {
        if (data2.index_alias === undefined) {
          const err9 = {
            instancePath: instancePath + "/record_ref",
            schemaPath: "#/$defs/RecordRef/required",
            keyword: "required",
            params: { missingProperty: "index_alias" },
            message: "must have required property '" + "index_alias" + "'",
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
        if (data2.record_id === undefined) {
          const err10 = {
            instancePath: instancePath + "/record_ref",
            schemaPath: "#/$defs/RecordRef/required",
            keyword: "required",
            params: { missingProperty: "record_id" },
            message: "must have required property '" + "record_id" + "'",
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
        for (const key1 in data2) {
          if (!(key1 === "index_alias" || key1 === "record_id")) {
            const err11 = {
              instancePath: instancePath + "/record_ref",
              schemaPath: "#/$defs/RecordRef/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          }
        }
        if (data2.index_alias !== undefined) {
          if (typeof data2.index_alias !== "string") {
            const err12 = {
              instancePath: instancePath + "/record_ref/index_alias",
              schemaPath: "#/$defs/RecordRef/properties/index_alias/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
        }
        if (data2.record_id !== undefined) {
          if (typeof data2.record_id !== "string") {
            const err13 = {
              instancePath: instancePath + "/record_ref/record_id",
              schemaPath: "#/$defs/RecordRef/properties/record_id/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err13];
            } else {
              vErrors.push(err13);
            }
            errors++;
          }
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/record_ref",
          schemaPath: "#/$defs/RecordRef/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
      var _valid0 = _errs10 === errors;
      valid3 = valid3 || _valid0;
      const _errs18 = errors;
      if (data2 !== null) {
        const err15 = {
          instancePath: instancePath + "/record_ref",
          schemaPath: "#/properties/record_ref/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
      var _valid0 = _errs18 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err16 = {
          instancePath: instancePath + "/record_ref",
          schemaPath: "#/properties/record_ref/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      } else {
        errors = _errs9;
        if (vErrors !== null) {
          if (_errs9) {
            vErrors.length = _errs9;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
    if (data.values !== undefined) {
      let data6 = data.values;
      if (data6 && typeof data6 == "object" && !Array.isArray(data6)) {
        for (const key2 in data6) {
          const _errs23 = errors;
          if (typeof key2 !== "string") {
            const err17 = {
              instancePath: instancePath + "/values",
              schemaPath: "#/$defs/FieldId/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
              propertyName: key2,
            };
            if (vErrors === null) {
              vErrors = [err17];
            } else {
              vErrors.push(err17);
            }
            errors++;
          }
          if (
            !(
              key2 === "timestamp" ||
              key2 === "agent.id" ||
              key2 === "agent.name" ||
              key2 === "rule.id" ||
              key2 === "rule.level" ||
              key2 === "rule.groups" ||
              key2 === "data.srcip" ||
              key2 === "data.dstip" ||
              key2 === "vulnerability.id" ||
              key2 === "vulnerability.severity" ||
              key2 === "vulnerability.detected_at" ||
              key2 === "package.name" ||
              key2 === "package.version"
            )
          ) {
            const err18 = {
              instancePath: instancePath + "/values",
              schemaPath: "#/$defs/FieldId/enum",
              keyword: "enum",
              params: { allowedValues: schema63.enum },
              message: "must be equal to one of the allowed values",
              propertyName: key2,
            };
            if (vErrors === null) {
              vErrors = [err18];
            } else {
              vErrors.push(err18);
            }
            errors++;
          }
          var valid6 = _errs23 === errors;
          if (!valid6) {
            const err19 = {
              instancePath: instancePath + "/values",
              schemaPath: "#/properties/values/propertyNames",
              keyword: "propertyNames",
              params: { propertyName: key2 },
              message: "property name must be valid",
            };
            if (vErrors === null) {
              vErrors = [err19];
            } else {
              vErrors.push(err19);
            }
            errors++;
          }
        }
        for (const key3 in data6) {
          let data7 = data6[key3];
          const _errs29 = errors;
          let valid10 = false;
          const _errs30 = errors;
          if (typeof data7 !== "string") {
            const err20 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf/0/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err20];
            } else {
              vErrors.push(err20);
            }
            errors++;
          }
          var _valid1 = _errs30 === errors;
          valid10 = valid10 || _valid1;
          const _errs32 = errors;
          if (!(typeof data7 == "number" && !(data7 % 1) && !isNaN(data7) && isFinite(data7))) {
            const err21 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf/1/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err21];
            } else {
              vErrors.push(err21);
            }
            errors++;
          }
          var _valid1 = _errs32 === errors;
          valid10 = valid10 || _valid1;
          const _errs34 = errors;
          if (typeof data7 !== "boolean") {
            const err22 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf/2/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err22];
            } else {
              vErrors.push(err22);
            }
            errors++;
          }
          var _valid1 = _errs34 === errors;
          valid10 = valid10 || _valid1;
          const _errs36 = errors;
          if (Array.isArray(data7)) {
            const len0 = data7.length;
            for (let i0 = 0; i0 < len0; i0++) {
              if (typeof data7[i0] !== "string") {
                const err23 = {
                  instancePath:
                    instancePath +
                    "/values/" +
                    key3.replace(/~/g, "~0").replace(/\//g, "~1") +
                    "/" +
                    i0,
                  schemaPath: "#/$defs/EvidenceValue/anyOf/3/items/type",
                  keyword: "type",
                  params: { type: "string" },
                  message: "must be string",
                };
                if (vErrors === null) {
                  vErrors = [err23];
                } else {
                  vErrors.push(err23);
                }
                errors++;
              }
            }
          } else {
            const err24 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf/3/type",
              keyword: "type",
              params: { type: "array" },
              message: "must be array",
            };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
          }
          var _valid1 = _errs36 === errors;
          valid10 = valid10 || _valid1;
          const _errs40 = errors;
          if (data7 !== null) {
            const err25 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf/4/type",
              keyword: "type",
              params: { type: "null" },
              message: "must be null",
            };
            if (vErrors === null) {
              vErrors = [err25];
            } else {
              vErrors.push(err25);
            }
            errors++;
          }
          var _valid1 = _errs40 === errors;
          valid10 = valid10 || _valid1;
          if (!valid10) {
            const err26 = {
              instancePath:
                instancePath + "/values/" + key3.replace(/~/g, "~0").replace(/\//g, "~1"),
              schemaPath: "#/$defs/EvidenceValue/anyOf",
              keyword: "anyOf",
              params: {},
              message: "must match a schema in anyOf",
            };
            if (vErrors === null) {
              vErrors = [err26];
            } else {
              vErrors.push(err26);
            }
            errors++;
          } else {
            errors = _errs29;
            if (vErrors !== null) {
              if (_errs29) {
                vErrors.length = _errs29;
              } else {
                vErrors = null;
              }
            }
          }
        }
      } else {
        const err27 = {
          instancePath: instancePath + "/values",
          schemaPath: "#/properties/values/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err27];
        } else {
          vErrors.push(err27);
        }
        errors++;
      }
    }
  } else {
    const err28 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err28];
    } else {
      vErrors.push(err28);
    }
    errors++;
  }
  validate82.errors = vErrors;
  return errors === 0;
}
validate82.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema130 = {
  additionalProperties: false,
  properties: {
    displayed_rows: { minimum: 0, title: "Displayed Rows", type: "integer" },
    environment_id: { $ref: "#/$defs/ContentId" },
    filters: { items: { $ref: "#/$defs/Filter" }, title: "Filters", type: "array" },
    index_family: { $ref: "#/$defs/IndexFamily" },
    policy_hash: { $ref: "#/$defs/PolicyHash" },
    snapshot: { $ref: "#/$defs/SnapshotKind" },
    template_id: { $ref: "#/$defs/TemplateId" },
    visibility: { $ref: "#/$defs/Visibility" },
  },
  required: [
    "environment_id",
    "template_id",
    "index_family",
    "filters",
    "visibility",
    "policy_hash",
    "snapshot",
    "displayed_rows",
  ],
  title: "FetchScope",
  type: "object",
};
const schema132 = { enum: ["alerts", "vulnerabilities"], title: "IndexFamily", type: "string" };
const schema133 = {
  maxLength: 64,
  minLength: 64,
  pattern: "^[0-9a-f]*[1-9a-f][0-9a-f]*$",
  type: "string",
};
const pattern35 = new RegExp("^[0-9a-f]*[1-9a-f][0-9a-f]*$", "u");
function validate85(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate85.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.environment_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "environment_id" },
        message: "must have required property '" + "environment_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.template_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "template_id" },
        message: "must have required property '" + "template_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.index_family === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "index_family" },
        message: "must have required property '" + "index_family" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.filters === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "filters" },
        message: "must have required property '" + "filters" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.visibility === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "visibility" },
        message: "must have required property '" + "visibility" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.policy_hash === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "policy_hash" },
        message: "must have required property '" + "policy_hash" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.snapshot === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "snapshot" },
        message: "must have required property '" + "snapshot" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.displayed_rows === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "displayed_rows" },
        message: "must have required property '" + "displayed_rows" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "displayed_rows" ||
          key0 === "environment_id" ||
          key0 === "filters" ||
          key0 === "index_family" ||
          key0 === "policy_hash" ||
          key0 === "snapshot" ||
          key0 === "template_id" ||
          key0 === "visibility"
        )
      ) {
        const err8 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.displayed_rows !== undefined) {
      let data0 = data.displayed_rows;
      if (!(typeof data0 == "number" && !(data0 % 1) && !isNaN(data0) && isFinite(data0))) {
        const err9 = {
          instancePath: instancePath + "/displayed_rows",
          schemaPath: "#/properties/displayed_rows/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
      if (typeof data0 == "number" && isFinite(data0)) {
        if (data0 < 0 || isNaN(data0)) {
          const err10 = {
            instancePath: instancePath + "/displayed_rows",
            schemaPath: "#/properties/displayed_rows/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
      }
    }
    if (data.environment_id !== undefined) {
      let data1 = data.environment_id;
      if (typeof data1 === "string") {
        if (!pattern4.test(data1)) {
          const err11 = {
            instancePath: instancePath + "/environment_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err11];
          } else {
            vErrors.push(err11);
          }
          errors++;
        }
      } else {
        const err12 = {
          instancePath: instancePath + "/environment_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.filters !== undefined) {
      let data2 = data.filters;
      if (Array.isArray(data2)) {
        const len0 = data2.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate47(data2[i0], {
              instancePath: instancePath + "/filters/" + i0,
              parentData: data2,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate47.errors : vErrors.concat(validate47.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err13 = {
          instancePath: instancePath + "/filters",
          schemaPath: "#/properties/filters/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
    if (data.index_family !== undefined) {
      let data4 = data.index_family;
      if (typeof data4 !== "string") {
        const err14 = {
          instancePath: instancePath + "/index_family",
          schemaPath: "#/$defs/IndexFamily/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
      if (!(data4 === "alerts" || data4 === "vulnerabilities")) {
        const err15 = {
          instancePath: instancePath + "/index_family",
          schemaPath: "#/$defs/IndexFamily/enum",
          keyword: "enum",
          params: { allowedValues: schema132.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.policy_hash !== undefined) {
      let data5 = data.policy_hash;
      if (typeof data5 === "string") {
        if (func2(data5) > 64) {
          const err16 = {
            instancePath: instancePath + "/policy_hash",
            schemaPath: "#/$defs/PolicyHash/maxLength",
            keyword: "maxLength",
            params: { limit: 64 },
            message: "must NOT have more than 64 characters",
          };
          if (vErrors === null) {
            vErrors = [err16];
          } else {
            vErrors.push(err16);
          }
          errors++;
        }
        if (func2(data5) < 64) {
          const err17 = {
            instancePath: instancePath + "/policy_hash",
            schemaPath: "#/$defs/PolicyHash/minLength",
            keyword: "minLength",
            params: { limit: 64 },
            message: "must NOT have fewer than 64 characters",
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
        if (!pattern35.test(data5)) {
          const err18 = {
            instancePath: instancePath + "/policy_hash",
            schemaPath: "#/$defs/PolicyHash/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]*[1-9a-f][0-9a-f]*$" },
            message: 'must match pattern "' + "^[0-9a-f]*[1-9a-f][0-9a-f]*$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
      } else {
        const err19 = {
          instancePath: instancePath + "/policy_hash",
          schemaPath: "#/$defs/PolicyHash/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
    }
    if (data.snapshot !== undefined) {
      let data6 = data.snapshot;
      if (typeof data6 !== "string") {
        const err20 = {
          instancePath: instancePath + "/snapshot",
          schemaPath: "#/$defs/SnapshotKind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
      if (!(data6 === "pit" || data6 === "first_page_only")) {
        const err21 = {
          instancePath: instancePath + "/snapshot",
          schemaPath: "#/$defs/SnapshotKind/enum",
          keyword: "enum",
          params: { allowedValues: schema81.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err21];
        } else {
          vErrors.push(err21);
        }
        errors++;
      }
    }
    if (data.template_id !== undefined) {
      let data7 = data.template_id;
      if (typeof data7 !== "string") {
        const err22 = {
          instancePath: instancePath + "/template_id",
          schemaPath: "#/$defs/TemplateId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
      if (
        !(
          data7 === "alerts_rows_v1" ||
          data7 === "alerts_count_v1" ||
          data7 === "alerts_group_v1" ||
          data7 === "vulnerabilities_rows_v1" ||
          data7 === "vulnerabilities_count_v1" ||
          data7 === "vulnerabilities_group_v1"
        )
      ) {
        const err23 = {
          instancePath: instancePath + "/template_id",
          schemaPath: "#/$defs/TemplateId/enum",
          keyword: "enum",
          params: { allowedValues: schema87.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err23];
        } else {
          vErrors.push(err23);
        }
        errors++;
      }
    }
    if (data.visibility !== undefined) {
      let data8 = data.visibility;
      if (typeof data8 !== "string") {
        const err24 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err24];
        } else {
          vErrors.push(err24);
        }
        errors++;
      }
      if (!(data8 === "full" || data8 === "filtered" || data8 === "unknown")) {
        const err25 = {
          instancePath: instancePath + "/visibility",
          schemaPath: "#/$defs/Visibility/enum",
          keyword: "enum",
          params: { allowedValues: schema117.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err25];
        } else {
          vErrors.push(err25);
        }
        errors++;
      }
    }
  } else {
    const err26 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err26];
    } else {
      vErrors.push(err26);
    }
    errors++;
  }
  validate85.errors = vErrors;
  return errors === 0;
}
validate85.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate38(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate38.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.fetch_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "fetch_id" },
        message: "must have required property '" + "fetch_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.topic_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.state === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "state" },
        message: "must have required property '" + "state" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.scope === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "scope" },
        message: "must have required property '" + "scope" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.window === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "window" },
        message: "must have required property '" + "window" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.columns === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "columns" },
        message: "must have required property '" + "columns" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.rows === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "rows" },
        message: "must have required property '" + "rows" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.checks === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "checks" },
        message: "must have required property '" + "checks" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    if (data.snapshot === undefined) {
      const err8 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "snapshot" },
        message: "must have required property '" + "snapshot" + "'",
      };
      if (vErrors === null) {
        vErrors = [err8];
      } else {
        vErrors.push(err8);
      }
      errors++;
    }
    if (data.items === undefined) {
      const err9 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "items" },
        message: "must have required property '" + "items" + "'",
      };
      if (vErrors === null) {
        vErrors = [err9];
      } else {
        vErrors.push(err9);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema56.properties, key0)) {
        const err10 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.bucket_completeness !== undefined) {
      let data0 = data.bucket_completeness;
      if (typeof data0 !== "string") {
        const err11 = {
          instancePath: instancePath + "/bucket_completeness",
          schemaPath: "#/properties/bucket_completeness/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      if (!(data0 === "complete" || data0 === "partial" || data0 === "unknown")) {
        const err12 = {
          instancePath: instancePath + "/bucket_completeness",
          schemaPath: "#/properties/bucket_completeness/enum",
          keyword: "enum",
          params: { allowedValues: schema56.properties.bucket_completeness.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.buckets !== undefined) {
      let data1 = data.buckets;
      if (Array.isArray(data1)) {
        const len0 = data1.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate39(data1[i0], {
              instancePath: instancePath + "/buckets/" + i0,
              parentData: data1,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate39.errors : vErrors.concat(validate39.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err13 = {
          instancePath: instancePath + "/buckets",
          schemaPath: "#/properties/buckets/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
    if (data.checks !== undefined) {
      let data3 = data.checks;
      if (Array.isArray(data3)) {
        const len1 = data3.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate41(data3[i1], {
              instancePath: instancePath + "/checks/" + i1,
              parentData: data3,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate41.errors : vErrors.concat(validate41.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/checks",
          schemaPath: "#/properties/checks/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.columns !== undefined) {
      let data5 = data.columns;
      if (Array.isArray(data5)) {
        const len2 = data5.length;
        for (let i2 = 0; i2 < len2; i2++) {
          if (
            !validate43(data5[i2], {
              instancePath: instancePath + "/columns/" + i2,
              parentData: data5,
              parentDataProperty: i2,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate43.errors : vErrors.concat(validate43.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/columns",
          schemaPath: "#/properties/columns/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.count !== undefined) {
      let data7 = data.count;
      const _errs14 = errors;
      let valid7 = false;
      const _errs15 = errors;
      if (data7 && typeof data7 == "object" && !Array.isArray(data7)) {
        if (data7.value === undefined) {
          const err16 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "value" },
            message: "must have required property '" + "value" + "'",
          };
          if (vErrors === null) {
            vErrors = [err16];
          } else {
            vErrors.push(err16);
          }
          errors++;
        }
        if (data7.relation === undefined) {
          const err17 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "relation" },
            message: "must have required property '" + "relation" + "'",
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
        if (data7.scope === undefined) {
          const err18 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "scope" },
            message: "must have required property '" + "scope" + "'",
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
        if (data7.computed_by === undefined) {
          const err19 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "computed_by" },
            message: "must have required property '" + "computed_by" + "'",
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
        for (const key1 in data7) {
          if (
            !(
              key1 === "approximate" ||
              key1 === "computed_by" ||
              key1 === "relation" ||
              key1 === "scope" ||
              key1 === "value"
            )
          ) {
            const err20 = {
              instancePath: instancePath + "/count",
              schemaPath: "#/$defs/Count/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err20];
            } else {
              vErrors.push(err20);
            }
            errors++;
          }
        }
        if (data7.approximate !== undefined) {
          if (typeof data7.approximate !== "boolean") {
            const err21 = {
              instancePath: instancePath + "/count/approximate",
              schemaPath: "#/$defs/Count/properties/approximate/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err21];
            } else {
              vErrors.push(err21);
            }
            errors++;
          }
        }
        if (data7.computed_by !== undefined) {
          let data9 = data7.computed_by;
          if (typeof data9 !== "string") {
            const err22 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err22];
            } else {
              vErrors.push(err22);
            }
            errors++;
          }
          if ("indexer" !== data9) {
            const err23 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/const",
              keyword: "const",
              params: { allowedValue: "indexer" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err23];
            } else {
              vErrors.push(err23);
            }
            errors++;
          }
        }
        if (data7.relation !== undefined) {
          let data10 = data7.relation;
          if (typeof data10 !== "string") {
            const err24 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
          }
          if (!(data10 === "eq" || data10 === "gte")) {
            const err25 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.relation.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err25];
            } else {
              vErrors.push(err25);
            }
            errors++;
          }
        }
        if (data7.scope !== undefined) {
          let data11 = data7.scope;
          if (typeof data11 !== "string") {
            const err26 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err26];
            } else {
              vErrors.push(err26);
            }
            errors++;
          }
          if (!(data11 === "matching_visible_records" || data11 === "bucket_visible_records")) {
            const err27 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.scope.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err27];
            } else {
              vErrors.push(err27);
            }
            errors++;
          }
        }
        if (data7.value !== undefined) {
          let data12 = data7.value;
          if (!(typeof data12 == "number" && !(data12 % 1) && !isNaN(data12) && isFinite(data12))) {
            const err28 = {
              instancePath: instancePath + "/count/value",
              schemaPath: "#/$defs/Count/properties/value/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err28];
            } else {
              vErrors.push(err28);
            }
            errors++;
          }
          if (typeof data12 == "number" && isFinite(data12)) {
            if (data12 < 0 || isNaN(data12)) {
              const err29 = {
                instancePath: instancePath + "/count/value",
                schemaPath: "#/$defs/Count/properties/value/minimum",
                keyword: "minimum",
                params: { comparison: ">=", limit: 0 },
                message: "must be >= 0",
              };
              if (vErrors === null) {
                vErrors = [err29];
              } else {
                vErrors.push(err29);
              }
              errors++;
            }
          }
        }
      } else {
        const err30 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/$defs/Count/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err30];
        } else {
          vErrors.push(err30);
        }
        errors++;
      }
      var _valid0 = _errs15 === errors;
      valid7 = valid7 || _valid0;
      const _errs29 = errors;
      if (data7 !== null) {
        const err31 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err31];
        } else {
          vErrors.push(err31);
        }
        errors++;
      }
      var _valid0 = _errs29 === errors;
      valid7 = valid7 || _valid0;
      if (!valid7) {
        const err32 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err32];
        } else {
          vErrors.push(err32);
        }
        errors++;
      } else {
        errors = _errs14;
        if (vErrors !== null) {
          if (_errs14) {
            vErrors.length = _errs14;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.empty_proof !== undefined) {
      let data13 = data.empty_proof;
      const _errs32 = errors;
      let valid10 = false;
      const _errs33 = errors;
      if (
        !validate45(data13, {
          instancePath: instancePath + "/empty_proof",
          parentData: data,
          parentDataProperty: "empty_proof",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate45.errors : vErrors.concat(validate45.errors);
        errors = vErrors.length;
      }
      var _valid1 = _errs33 === errors;
      valid10 = valid10 || _valid1;
      const _errs34 = errors;
      if (data13 !== null) {
        const err33 = {
          instancePath: instancePath + "/empty_proof",
          schemaPath: "#/properties/empty_proof/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err33];
        } else {
          vErrors.push(err33);
        }
        errors++;
      }
      var _valid1 = _errs34 === errors;
      valid10 = valid10 || _valid1;
      if (!valid10) {
        const err34 = {
          instancePath: instancePath + "/empty_proof",
          schemaPath: "#/properties/empty_proof/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err34];
        } else {
          vErrors.push(err34);
        }
        errors++;
      } else {
        errors = _errs32;
        if (vErrors !== null) {
          if (_errs32) {
            vErrors.length = _errs32;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.error !== undefined) {
      let data14 = data.error;
      const _errs37 = errors;
      let valid11 = false;
      const _errs38 = errors;
      if (
        !validate79(data14, {
          instancePath: instancePath + "/error",
          parentData: data,
          parentDataProperty: "error",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate79.errors : vErrors.concat(validate79.errors);
        errors = vErrors.length;
      }
      var _valid2 = _errs38 === errors;
      valid11 = valid11 || _valid2;
      const _errs39 = errors;
      if (data14 !== null) {
        const err35 = {
          instancePath: instancePath + "/error",
          schemaPath: "#/properties/error/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err35];
        } else {
          vErrors.push(err35);
        }
        errors++;
      }
      var _valid2 = _errs39 === errors;
      valid11 = valid11 || _valid2;
      if (!valid11) {
        const err36 = {
          instancePath: instancePath + "/error",
          schemaPath: "#/properties/error/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err36];
        } else {
          vErrors.push(err36);
        }
        errors++;
      } else {
        errors = _errs37;
        if (vErrors !== null) {
          if (_errs37) {
            vErrors.length = _errs37;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.fetch_id !== undefined) {
      let data15 = data.fetch_id;
      if (typeof data15 === "string") {
        if (!pattern4.test(data15)) {
          const err37 = {
            instancePath: instancePath + "/fetch_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err37];
          } else {
            vErrors.push(err37);
          }
          errors++;
        }
      } else {
        const err38 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err38];
        } else {
          vErrors.push(err38);
        }
        errors++;
      }
    }
    if (data.items !== undefined) {
      let data16 = data.items;
      if (Array.isArray(data16)) {
        const len3 = data16.length;
        for (let i3 = 0; i3 < len3; i3++) {
          if (
            !validate50(data16[i3], {
              instancePath: instancePath + "/items/" + i3,
              parentData: data16,
              parentDataProperty: i3,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate50.errors : vErrors.concat(validate50.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err39 = {
          instancePath: instancePath + "/items",
          schemaPath: "#/properties/items/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err39];
        } else {
          vErrors.push(err39);
        }
        errors++;
      }
    }
    if (data.message !== undefined) {
      let data18 = data.message;
      const _errs48 = errors;
      let valid15 = false;
      const _errs49 = errors;
      if (typeof data18 !== "string") {
        const err40 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err40];
        } else {
          vErrors.push(err40);
        }
        errors++;
      }
      var _valid3 = _errs49 === errors;
      valid15 = valid15 || _valid3;
      const _errs51 = errors;
      if (data18 !== null) {
        const err41 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err41];
        } else {
          vErrors.push(err41);
        }
        errors++;
      }
      var _valid3 = _errs51 === errors;
      valid15 = valid15 || _valid3;
      if (!valid15) {
        const err42 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err42];
        } else {
          vErrors.push(err42);
        }
        errors++;
      } else {
        errors = _errs48;
        if (vErrors !== null) {
          if (_errs48) {
            vErrors.length = _errs48;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.next_cursor !== undefined) {
      let data19 = data.next_cursor;
      const _errs54 = errors;
      let valid16 = false;
      const _errs55 = errors;
      if (typeof data19 !== "string") {
        const err43 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err43];
        } else {
          vErrors.push(err43);
        }
        errors++;
      }
      var _valid4 = _errs55 === errors;
      valid16 = valid16 || _valid4;
      const _errs57 = errors;
      if (data19 !== null) {
        const err44 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err44];
        } else {
          vErrors.push(err44);
        }
        errors++;
      }
      var _valid4 = _errs57 === errors;
      valid16 = valid16 || _valid4;
      if (!valid16) {
        const err45 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err45];
        } else {
          vErrors.push(err45);
        }
        errors++;
      } else {
        errors = _errs54;
        if (vErrors !== null) {
          if (_errs54) {
            vErrors.length = _errs54;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.rows !== undefined) {
      let data20 = data.rows;
      if (Array.isArray(data20)) {
        const len4 = data20.length;
        for (let i4 = 0; i4 < len4; i4++) {
          if (
            !validate82(data20[i4], {
              instancePath: instancePath + "/rows/" + i4,
              parentData: data20,
              parentDataProperty: i4,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err46 = {
          instancePath: instancePath + "/rows",
          schemaPath: "#/properties/rows/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err46];
        } else {
          vErrors.push(err46);
        }
        errors++;
      }
    }
    if (data.scope !== undefined) {
      if (
        !validate85(data.scope, {
          instancePath: instancePath + "/scope",
          parentData: data,
          parentDataProperty: "scope",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate85.errors : vErrors.concat(validate85.errors);
        errors = vErrors.length;
      }
    }
    if (data.snapshot !== undefined) {
      if (
        !validate51(data.snapshot, {
          instancePath: instancePath + "/snapshot",
          parentData: data,
          parentDataProperty: "snapshot",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate51.errors : vErrors.concat(validate51.errors);
        errors = vErrors.length;
      }
    }
    if (data.snapshot_at !== undefined) {
      let data24 = data.snapshot_at;
      const _errs65 = errors;
      let valid19 = false;
      const _errs66 = errors;
      if (typeof data24 === "string") {
        if (!formats4.validate(data24)) {
          const err47 = {
            instancePath: instancePath + "/snapshot_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err47];
          } else {
            vErrors.push(err47);
          }
          errors++;
        }
      } else {
        const err48 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err48];
        } else {
          vErrors.push(err48);
        }
        errors++;
      }
      var _valid5 = _errs66 === errors;
      valid19 = valid19 || _valid5;
      const _errs69 = errors;
      if (data24 !== null) {
        const err49 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/properties/snapshot_at/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err49];
        } else {
          vErrors.push(err49);
        }
        errors++;
      }
      var _valid5 = _errs69 === errors;
      valid19 = valid19 || _valid5;
      if (!valid19) {
        const err50 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/properties/snapshot_at/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err50];
        } else {
          vErrors.push(err50);
        }
        errors++;
      } else {
        errors = _errs65;
        if (vErrors !== null) {
          if (_errs65) {
            vErrors.length = _errs65;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.state !== undefined) {
      let data25 = data.state;
      if (typeof data25 !== "string") {
        const err51 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/FetchState/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err51];
        } else {
          vErrors.push(err51);
        }
        errors++;
      }
      if (
        !(
          data25 === "rows" ||
          data25 === "empty" ||
          data25 === "filtered" ||
          data25 === "denied" ||
          data25 === "unavailable"
        )
      ) {
        const err52 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/FetchState/enum",
          keyword: "enum",
          params: { allowedValues: schema138.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err52];
        } else {
          vErrors.push(err52);
        }
        errors++;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
    if (data.window !== undefined) {
      if (
        !validate58(data.window, {
          instancePath: instancePath + "/window",
          parentData: data,
          parentDataProperty: "window",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate58.errors : vErrors.concat(validate58.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err53 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err53];
    } else {
      vErrors.push(err53);
    }
    errors++;
  }
  validate38.errors = vErrors;
  return errors === 0;
}
validate38.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate22(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate22.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.topic_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.ordinal === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "ordinal" },
        message: "must have required property '" + "ordinal" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.missing === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "missing" },
        message: "must have required property '" + "missing" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.tables === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "tables" },
        message: "must have required property '" + "tables" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.checks === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "checks" },
        message: "must have required property '" + "checks" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.judgment === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "judgment" },
        message: "must have required property '" + "judgment" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "checks" ||
          key0 === "document" ||
          key0 === "judgment" ||
          key0 === "missing" ||
          key0 === "ordinal" ||
          key0 === "tables" ||
          key0 === "topic_id"
        )
      ) {
        const err6 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.checks !== undefined) {
      let data0 = data.checks;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate23(data0[i0], {
              instancePath: instancePath + "/checks/" + i0,
              parentData: data0,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate23.errors : vErrors.concat(validate23.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err7 = {
          instancePath: instancePath + "/checks",
          schemaPath: "#/properties/checks/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.document !== undefined) {
      let data2 = data.document;
      const _errs6 = errors;
      let valid3 = false;
      const _errs7 = errors;
      if (
        !validate27(data2, {
          instancePath: instancePath + "/document",
          parentData: data,
          parentDataProperty: "document",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate27.errors : vErrors.concat(validate27.errors);
        errors = vErrors.length;
      }
      var _valid0 = _errs7 === errors;
      valid3 = valid3 || _valid0;
      const _errs8 = errors;
      if (data2 !== null) {
        const err8 = {
          instancePath: instancePath + "/document",
          schemaPath: "#/properties/document/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      var _valid0 = _errs8 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err9 = {
          instancePath: instancePath + "/document",
          schemaPath: "#/properties/document/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      } else {
        errors = _errs6;
        if (vErrors !== null) {
          if (_errs6) {
            vErrors.length = _errs6;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.judgment !== undefined) {
      if (
        !validate29(data.judgment, {
          instancePath: instancePath + "/judgment",
          parentData: data,
          parentDataProperty: "judgment",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate29.errors : vErrors.concat(validate29.errors);
        errors = vErrors.length;
      }
    }
    if (data.missing !== undefined) {
      let data4 = data.missing;
      if (Array.isArray(data4)) {
        const len1 = data4.length;
        for (let i1 = 0; i1 < len1; i1++) {
          let data5 = data4[i1];
          if (typeof data5 !== "string") {
            const err10 = {
              instancePath: instancePath + "/missing/" + i1,
              schemaPath: "#/properties/missing/items/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err10];
            } else {
              vErrors.push(err10);
            }
            errors++;
          }
          if (!(data5 === "public_document" || data5 === "playbook")) {
            const err11 = {
              instancePath: instancePath + "/missing/" + i1,
              schemaPath: "#/properties/missing/items/enum",
              keyword: "enum",
              params: { allowedValues: schema33.properties.missing.items.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err11];
            } else {
              vErrors.push(err11);
            }
            errors++;
          }
        }
      } else {
        const err12 = {
          instancePath: instancePath + "/missing",
          schemaPath: "#/properties/missing/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.ordinal !== undefined) {
      let data6 = data.ordinal;
      if (!(typeof data6 == "number" && !(data6 % 1) && !isNaN(data6) && isFinite(data6))) {
        const err13 = {
          instancePath: instancePath + "/ordinal",
          schemaPath: "#/properties/ordinal/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
      if (typeof data6 == "number" && isFinite(data6)) {
        if (data6 < 0 || isNaN(data6)) {
          const err14 = {
            instancePath: instancePath + "/ordinal",
            schemaPath: "#/properties/ordinal/minimum",
            keyword: "minimum",
            params: { comparison: ">=", limit: 0 },
            message: "must be >= 0",
          };
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        }
      }
    }
    if (data.tables !== undefined) {
      let data7 = data.tables;
      if (Array.isArray(data7)) {
        const len2 = data7.length;
        for (let i2 = 0; i2 < len2; i2++) {
          if (
            !validate38(data7[i2], {
              instancePath: instancePath + "/tables/" + i2,
              parentData: data7,
              parentDataProperty: i2,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate38.errors : vErrors.concat(validate38.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/tables",
          schemaPath: "#/properties/tables/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err16 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err16];
    } else {
      vErrors.push(err16);
    }
    errors++;
  }
  validate22.errors = vErrors;
  return errors === 0;
}
validate22.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema139 = {
  additionalProperties: false,
  properties: {
    kind: {
      enum: [
        "missing_slots",
        "ambiguous_scope",
        "missing_subject",
        "semantic_suggestion",
        "model_selection",
      ],
      title: "Kind",
      type: "string",
    },
    question: { title: "Question", type: "string" },
    slots: { items: { type: "string" }, title: "Slots", type: "array" },
    suggested_topic: { anyOf: [{ $ref: "#/$defs/ContentId" }, { type: "null" }], default: null },
  },
  required: ["kind", "question", "slots"],
  title: "Clarify",
  type: "object",
};
function validate94(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate94.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.kind === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "kind" },
        message: "must have required property '" + "kind" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.question === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "question" },
        message: "must have required property '" + "question" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.slots === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "slots" },
        message: "must have required property '" + "slots" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(key0 === "kind" || key0 === "question" || key0 === "slots" || key0 === "suggested_topic")
      ) {
        const err3 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
    if (data.kind !== undefined) {
      let data0 = data.kind;
      if (typeof data0 !== "string") {
        const err4 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
      if (
        !(
          data0 === "missing_slots" ||
          data0 === "ambiguous_scope" ||
          data0 === "missing_subject" ||
          data0 === "semantic_suggestion" ||
          data0 === "model_selection"
        )
      ) {
        const err5 = {
          instancePath: instancePath + "/kind",
          schemaPath: "#/properties/kind/enum",
          keyword: "enum",
          params: { allowedValues: schema139.properties.kind.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.question !== undefined) {
      if (typeof data.question !== "string") {
        const err6 = {
          instancePath: instancePath + "/question",
          schemaPath: "#/properties/question/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.slots !== undefined) {
      let data2 = data.slots;
      if (Array.isArray(data2)) {
        const len0 = data2.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (typeof data2[i0] !== "string") {
            const err7 = {
              instancePath: instancePath + "/slots/" + i0,
              schemaPath: "#/properties/slots/items/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err7];
            } else {
              vErrors.push(err7);
            }
            errors++;
          }
        }
      } else {
        const err8 = {
          instancePath: instancePath + "/slots",
          schemaPath: "#/properties/slots/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.suggested_topic !== undefined) {
      let data4 = data.suggested_topic;
      const _errs11 = errors;
      let valid3 = false;
      const _errs12 = errors;
      if (typeof data4 === "string") {
        if (!pattern4.test(data4)) {
          const err9 = {
            instancePath: instancePath + "/suggested_topic",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/suggested_topic",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
      var _valid0 = _errs12 === errors;
      valid3 = valid3 || _valid0;
      const _errs15 = errors;
      if (data4 !== null) {
        const err11 = {
          instancePath: instancePath + "/suggested_topic",
          schemaPath: "#/properties/suggested_topic/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid0 = _errs15 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err12 = {
          instancePath: instancePath + "/suggested_topic",
          schemaPath: "#/properties/suggested_topic/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      } else {
        errors = _errs11;
        if (vErrors !== null) {
          if (_errs11) {
            vErrors.length = _errs11;
          } else {
            vErrors = null;
          }
        }
      }
    }
  } else {
    const err13 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err13];
    } else {
      vErrors.push(err13);
    }
    errors++;
  }
  validate94.errors = vErrors;
  return errors === 0;
}
validate94.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema142 = {
  additionalProperties: false,
  properties: {
    reason: { $ref: "#/$defs/LeftOutReason" },
    retryable: { title: "Retryable", type: "boolean" },
    stage: { enum: ["fetch", "checks", "judgment"], title: "Stage", type: "string" },
    topic_id: { $ref: "#/$defs/TopicId" },
  },
  required: ["topic_id", "stage", "reason", "retryable"],
  title: "LeftOut",
  type: "object",
};
const schema143 = {
  enum: [
    "context_exceeded",
    "budget_exceeded",
    "model_unavailable",
    "guardrail_blocked",
    "invalid_output",
    "all_removed",
    "token_count_unavailable",
    "deadline_exceeded",
    "capacity_limited",
    "evidence_unavailable",
  ],
  title: "LeftOutReason",
  type: "string",
};
function validate96(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate96.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.topic_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.stage === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "stage" },
        message: "must have required property '" + "stage" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.reason === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "reason" },
        message: "must have required property '" + "reason" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.retryable === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "retryable" },
        message: "must have required property '" + "retryable" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "reason" || key0 === "retryable" || key0 === "stage" || key0 === "topic_id")) {
        const err4 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.reason !== undefined) {
      let data0 = data.reason;
      if (typeof data0 !== "string") {
        const err5 = {
          instancePath: instancePath + "/reason",
          schemaPath: "#/$defs/LeftOutReason/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
      if (
        !(
          data0 === "context_exceeded" ||
          data0 === "budget_exceeded" ||
          data0 === "model_unavailable" ||
          data0 === "guardrail_blocked" ||
          data0 === "invalid_output" ||
          data0 === "all_removed" ||
          data0 === "token_count_unavailable" ||
          data0 === "deadline_exceeded" ||
          data0 === "capacity_limited" ||
          data0 === "evidence_unavailable"
        )
      ) {
        const err6 = {
          instancePath: instancePath + "/reason",
          schemaPath: "#/$defs/LeftOutReason/enum",
          keyword: "enum",
          params: { allowedValues: schema143.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
    if (data.retryable !== undefined) {
      if (typeof data.retryable !== "boolean") {
        const err7 = {
          instancePath: instancePath + "/retryable",
          schemaPath: "#/properties/retryable/type",
          keyword: "type",
          params: { type: "boolean" },
          message: "must be boolean",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.stage !== undefined) {
      let data2 = data.stage;
      if (typeof data2 !== "string") {
        const err8 = {
          instancePath: instancePath + "/stage",
          schemaPath: "#/properties/stage/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
      if (!(data2 === "fetch" || data2 === "checks" || data2 === "judgment")) {
        const err9 = {
          instancePath: instancePath + "/stage",
          schemaPath: "#/properties/stage/enum",
          keyword: "enum",
          params: { allowedValues: schema142.properties.stage.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err10 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err10];
    } else {
      vErrors.push(err10);
    }
    errors++;
  }
  validate96.errors = vErrors;
  return errors === 0;
}
validate96.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema144 = {
  additionalProperties: false,
  properties: {
    content_repository: { title: "Content Repository", type: "string" },
    content_sha: { $ref: "#/$defs/GitSHA40" },
    contract_version: { const: "1", default: "1", title: "Contract Version", type: "string" },
    docs_manifest_sha256: { $ref: "#/$defs/SHA256" },
    docs_origin: { $ref: "#/$defs/HTTPSOrigin" },
    image_digest: { pattern: "^sha256:[0-9a-f]{64}$", title: "Image Digest", type: "string" },
    pack_sha256: { $ref: "#/$defs/SHA256" },
    service_sha: { $ref: "#/$defs/GitSHA40" },
  },
  required: [
    "service_sha",
    "content_repository",
    "content_sha",
    "pack_sha256",
    "image_digest",
    "docs_origin",
    "docs_manifest_sha256",
  ],
  title: "BuildProvenance",
  type: "object",
};
const schema147 = { pattern: "^https://[^/?#@\\s]+(?::[0-9]{1,5})?$", type: "string" };
const pattern40 = new RegExp("^https://[^/?#@\\s]+(?::[0-9]{1,5})?$", "u");
const pattern41 = new RegExp("^sha256:[0-9a-f]{64}$", "u");
function validate99(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate99.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.service_sha === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "service_sha" },
        message: "must have required property '" + "service_sha" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.content_repository === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "content_repository" },
        message: "must have required property '" + "content_repository" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.content_sha === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "content_sha" },
        message: "must have required property '" + "content_sha" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.pack_sha256 === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "pack_sha256" },
        message: "must have required property '" + "pack_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.image_digest === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "image_digest" },
        message: "must have required property '" + "image_digest" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.docs_origin === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "docs_origin" },
        message: "must have required property '" + "docs_origin" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.docs_manifest_sha256 === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "docs_manifest_sha256" },
        message: "must have required property '" + "docs_manifest_sha256" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "content_repository" ||
          key0 === "content_sha" ||
          key0 === "contract_version" ||
          key0 === "docs_manifest_sha256" ||
          key0 === "docs_origin" ||
          key0 === "image_digest" ||
          key0 === "pack_sha256" ||
          key0 === "service_sha"
        )
      ) {
        const err7 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
    }
    if (data.content_repository !== undefined) {
      if (typeof data.content_repository !== "string") {
        const err8 = {
          instancePath: instancePath + "/content_repository",
          schemaPath: "#/properties/content_repository/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      }
    }
    if (data.content_sha !== undefined) {
      let data1 = data.content_sha;
      if (typeof data1 === "string") {
        if (!pattern8.test(data1)) {
          const err9 = {
            instancePath: instancePath + "/content_sha",
            schemaPath: "#/$defs/GitSHA40/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{40}$" },
            message: 'must match pattern "' + "^[0-9a-f]{40}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/content_sha",
          schemaPath: "#/$defs/GitSHA40/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.contract_version !== undefined) {
      let data2 = data.contract_version;
      if (typeof data2 !== "string") {
        const err11 = {
          instancePath: instancePath + "/contract_version",
          schemaPath: "#/properties/contract_version/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      if ("1" !== data2) {
        const err12 = {
          instancePath: instancePath + "/contract_version",
          schemaPath: "#/properties/contract_version/const",
          keyword: "const",
          params: { allowedValue: "1" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.docs_manifest_sha256 !== undefined) {
      let data3 = data.docs_manifest_sha256;
      if (typeof data3 === "string") {
        if (!pattern10.test(data3)) {
          const err13 = {
            instancePath: instancePath + "/docs_manifest_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/docs_manifest_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.docs_origin !== undefined) {
      let data4 = data.docs_origin;
      if (typeof data4 === "string") {
        if (!pattern40.test(data4)) {
          const err15 = {
            instancePath: instancePath + "/docs_origin",
            schemaPath: "#/$defs/HTTPSOrigin/pattern",
            keyword: "pattern",
            params: { pattern: "^https://[^/?#@\\s]+(?::[0-9]{1,5})?$" },
            message: 'must match pattern "' + "^https://[^/?#@\\s]+(?::[0-9]{1,5})?$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err15];
          } else {
            vErrors.push(err15);
          }
          errors++;
        }
      } else {
        const err16 = {
          instancePath: instancePath + "/docs_origin",
          schemaPath: "#/$defs/HTTPSOrigin/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
    }
    if (data.image_digest !== undefined) {
      let data5 = data.image_digest;
      if (typeof data5 === "string") {
        if (!pattern41.test(data5)) {
          const err17 = {
            instancePath: instancePath + "/image_digest",
            schemaPath: "#/properties/image_digest/pattern",
            keyword: "pattern",
            params: { pattern: "^sha256:[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^sha256:[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/image_digest",
          schemaPath: "#/properties/image_digest/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
    }
    if (data.pack_sha256 !== undefined) {
      let data6 = data.pack_sha256;
      if (typeof data6 === "string") {
        if (!pattern10.test(data6)) {
          const err19 = {
            instancePath: instancePath + "/pack_sha256",
            schemaPath: "#/$defs/SHA256/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{64}$" },
            message: 'must match pattern "' + "^[0-9a-f]{64}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
      } else {
        const err20 = {
          instancePath: instancePath + "/pack_sha256",
          schemaPath: "#/$defs/SHA256/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      }
    }
    if (data.service_sha !== undefined) {
      let data7 = data.service_sha;
      if (typeof data7 === "string") {
        if (!pattern8.test(data7)) {
          const err21 = {
            instancePath: instancePath + "/service_sha",
            schemaPath: "#/$defs/GitSHA40/pattern",
            keyword: "pattern",
            params: { pattern: "^[0-9a-f]{40}$" },
            message: 'must match pattern "' + "^[0-9a-f]{40}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
        }
      } else {
        const err22 = {
          instancePath: instancePath + "/service_sha",
          schemaPath: "#/$defs/GitSHA40/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
    }
  } else {
    const err23 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err23];
    } else {
      vErrors.push(err23);
    }
    errors++;
  }
  validate99.errors = vErrors;
  return errors === 0;
}
validate99.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate21(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate21.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.question_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "question_id" },
        message: "must have required property '" + "question_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.environment_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "environment_id" },
        message: "must have required property '" + "environment_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.language === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "language" },
        message: "must have required property '" + "language" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.status === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "status" },
        message: "must have required property '" + "status" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.blocks === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "blocks" },
        message: "must have required property '" + "blocks" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.left_out === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "left_out" },
        message: "must have required property '" + "left_out" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.provenance === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "provenance" },
        message: "must have required property '" + "provenance" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.trace_id === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "trace_id" },
        message: "must have required property '" + "trace_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    if (data.feedback_receipt === undefined) {
      const err8 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "feedback_receipt" },
        message: "must have required property '" + "feedback_receipt" + "'",
      };
      if (vErrors === null) {
        vErrors = [err8];
      } else {
        vErrors.push(err8);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema32.properties, key0)) {
        const err9 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err9];
        } else {
          vErrors.push(err9);
        }
        errors++;
      }
    }
    if (data.blocks !== undefined) {
      let data0 = data.blocks;
      if (Array.isArray(data0)) {
        const len0 = data0.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate22(data0[i0], {
              instancePath: instancePath + "/blocks/" + i0,
              parentData: data0,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate22.errors : vErrors.concat(validate22.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/blocks",
          schemaPath: "#/properties/blocks/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.clarify !== undefined) {
      let data2 = data.clarify;
      const _errs6 = errors;
      let valid3 = false;
      const _errs7 = errors;
      if (
        !validate94(data2, {
          instancePath: instancePath + "/clarify",
          parentData: data,
          parentDataProperty: "clarify",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
        errors = vErrors.length;
      }
      var _valid0 = _errs7 === errors;
      valid3 = valid3 || _valid0;
      const _errs8 = errors;
      if (data2 !== null) {
        const err11 = {
          instancePath: instancePath + "/clarify",
          schemaPath: "#/properties/clarify/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      var _valid0 = _errs8 === errors;
      valid3 = valid3 || _valid0;
      if (!valid3) {
        const err12 = {
          instancePath: instancePath + "/clarify",
          schemaPath: "#/properties/clarify/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      } else {
        errors = _errs6;
        if (vErrors !== null) {
          if (_errs6) {
            vErrors.length = _errs6;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.environment_id !== undefined) {
      let data3 = data.environment_id;
      if (typeof data3 === "string") {
        if (!pattern4.test(data3)) {
          const err13 = {
            instancePath: instancePath + "/environment_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/environment_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.feedback_receipt !== undefined) {
      let data4 = data.feedback_receipt;
      if (typeof data4 === "string") {
        if (func2(data4) > 8192) {
          const err15 = {
            instancePath: instancePath + "/feedback_receipt",
            schemaPath: "#/properties/feedback_receipt/maxLength",
            keyword: "maxLength",
            params: { limit: 8192 },
            message: "must NOT have more than 8192 characters",
          };
          if (vErrors === null) {
            vErrors = [err15];
          } else {
            vErrors.push(err15);
          }
          errors++;
        }
      } else {
        const err16 = {
          instancePath: instancePath + "/feedback_receipt",
          schemaPath: "#/properties/feedback_receipt/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err16];
        } else {
          vErrors.push(err16);
        }
        errors++;
      }
    }
    if (data.followup_id !== undefined) {
      let data5 = data.followup_id;
      const _errs16 = errors;
      let valid5 = false;
      const _errs17 = errors;
      if (typeof data5 === "string") {
        if (!formats2.test(data5)) {
          const err17 = {
            instancePath: instancePath + "/followup_id",
            schemaPath: "#/properties/followup_id/anyOf/0/format",
            keyword: "format",
            params: { format: "uuid" },
            message: 'must match format "' + "uuid" + '"',
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
      } else {
        const err18 = {
          instancePath: instancePath + "/followup_id",
          schemaPath: "#/properties/followup_id/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err18];
        } else {
          vErrors.push(err18);
        }
        errors++;
      }
      var _valid1 = _errs17 === errors;
      valid5 = valid5 || _valid1;
      const _errs19 = errors;
      if (data5 !== null) {
        const err19 = {
          instancePath: instancePath + "/followup_id",
          schemaPath: "#/properties/followup_id/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err19];
        } else {
          vErrors.push(err19);
        }
        errors++;
      }
      var _valid1 = _errs19 === errors;
      valid5 = valid5 || _valid1;
      if (!valid5) {
        const err20 = {
          instancePath: instancePath + "/followup_id",
          schemaPath: "#/properties/followup_id/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err20];
        } else {
          vErrors.push(err20);
        }
        errors++;
      } else {
        errors = _errs16;
        if (vErrors !== null) {
          if (_errs16) {
            vErrors.length = _errs16;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.followup_revision !== undefined) {
      let data6 = data.followup_revision;
      const _errs22 = errors;
      let valid6 = false;
      const _errs23 = errors;
      if (!(typeof data6 == "number" && !(data6 % 1) && !isNaN(data6) && isFinite(data6))) {
        const err21 = {
          instancePath: instancePath + "/followup_revision",
          schemaPath: "#/properties/followup_revision/anyOf/0/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err21];
        } else {
          vErrors.push(err21);
        }
        errors++;
      }
      var _valid2 = _errs23 === errors;
      valid6 = valid6 || _valid2;
      const _errs25 = errors;
      if (data6 !== null) {
        const err22 = {
          instancePath: instancePath + "/followup_revision",
          schemaPath: "#/properties/followup_revision/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err22];
        } else {
          vErrors.push(err22);
        }
        errors++;
      }
      var _valid2 = _errs25 === errors;
      valid6 = valid6 || _valid2;
      if (!valid6) {
        const err23 = {
          instancePath: instancePath + "/followup_revision",
          schemaPath: "#/properties/followup_revision/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err23];
        } else {
          vErrors.push(err23);
        }
        errors++;
      } else {
        errors = _errs22;
        if (vErrors !== null) {
          if (_errs22) {
            vErrors.length = _errs22;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.language !== undefined) {
      let data7 = data.language;
      if (typeof data7 !== "string") {
        const err24 = {
          instancePath: instancePath + "/language",
          schemaPath: "#/properties/language/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err24];
        } else {
          vErrors.push(err24);
        }
        errors++;
      }
      if (!(data7 === "en" || data7 === "es")) {
        const err25 = {
          instancePath: instancePath + "/language",
          schemaPath: "#/properties/language/enum",
          keyword: "enum",
          params: { allowedValues: schema32.properties.language.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err25];
        } else {
          vErrors.push(err25);
        }
        errors++;
      }
    }
    if (data.left_out !== undefined) {
      let data8 = data.left_out;
      if (Array.isArray(data8)) {
        const len1 = data8.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate96(data8[i1], {
              instancePath: instancePath + "/left_out/" + i1,
              parentData: data8,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate96.errors : vErrors.concat(validate96.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err26 = {
          instancePath: instancePath + "/left_out",
          schemaPath: "#/properties/left_out/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err26];
        } else {
          vErrors.push(err26);
        }
        errors++;
      }
    }
    if (data.message !== undefined) {
      let data10 = data.message;
      const _errs33 = errors;
      let valid9 = false;
      const _errs34 = errors;
      if (typeof data10 !== "string") {
        const err27 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err27];
        } else {
          vErrors.push(err27);
        }
        errors++;
      }
      var _valid3 = _errs34 === errors;
      valid9 = valid9 || _valid3;
      const _errs36 = errors;
      if (data10 !== null) {
        const err28 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err28];
        } else {
          vErrors.push(err28);
        }
        errors++;
      }
      var _valid3 = _errs36 === errors;
      valid9 = valid9 || _valid3;
      if (!valid9) {
        const err29 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err29];
        } else {
          vErrors.push(err29);
        }
        errors++;
      } else {
        errors = _errs33;
        if (vErrors !== null) {
          if (_errs33) {
            vErrors.length = _errs33;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.provenance !== undefined) {
      if (
        !validate99(data.provenance, {
          instancePath: instancePath + "/provenance",
          parentData: data,
          parentDataProperty: "provenance",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate99.errors : vErrors.concat(validate99.errors);
        errors = vErrors.length;
      }
    }
    if (data.question_id !== undefined) {
      let data12 = data.question_id;
      if (typeof data12 === "string") {
        if (!formats2.test(data12)) {
          const err30 = {
            instancePath: instancePath + "/question_id",
            schemaPath: "#/properties/question_id/format",
            keyword: "format",
            params: { format: "uuid" },
            message: 'must match format "' + "uuid" + '"',
          };
          if (vErrors === null) {
            vErrors = [err30];
          } else {
            vErrors.push(err30);
          }
          errors++;
        }
      } else {
        const err31 = {
          instancePath: instancePath + "/question_id",
          schemaPath: "#/properties/question_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err31];
        } else {
          vErrors.push(err31);
        }
        errors++;
      }
    }
    if (data.schema_version !== undefined) {
      let data13 = data.schema_version;
      if (typeof data13 !== "string") {
        const err32 = {
          instancePath: instancePath + "/schema_version",
          schemaPath: "#/properties/schema_version/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err32];
        } else {
          vErrors.push(err32);
        }
        errors++;
      }
      if ("1" !== data13) {
        const err33 = {
          instancePath: instancePath + "/schema_version",
          schemaPath: "#/properties/schema_version/const",
          keyword: "const",
          params: { allowedValue: "1" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err33];
        } else {
          vErrors.push(err33);
        }
        errors++;
      }
    }
    if (data.status !== undefined) {
      let data14 = data.status;
      if (typeof data14 !== "string") {
        const err34 = {
          instancePath: instancePath + "/status",
          schemaPath: "#/$defs/AnswerStatus/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err34];
        } else {
          vErrors.push(err34);
        }
        errors++;
      }
      if (
        !(
          data14 === "answered" ||
          data14 === "partial" ||
          data14 === "clarify" ||
          data14 === "refused"
        )
      ) {
        const err35 = {
          instancePath: instancePath + "/status",
          schemaPath: "#/$defs/AnswerStatus/enum",
          keyword: "enum",
          params: { allowedValues: schema150.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err35];
        } else {
          vErrors.push(err35);
        }
        errors++;
      }
    }
    if (data.trace_id !== undefined) {
      if (typeof data.trace_id !== "string") {
        const err36 = {
          instancePath: instancePath + "/trace_id",
          schemaPath: "#/properties/trace_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err36];
        } else {
          vErrors.push(err36);
        }
        errors++;
      }
    }
  } else {
    const err37 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err37];
    } else {
      vErrors.push(err37);
    }
    errors++;
  }
  validate21.errors = vErrors;
  return errors === 0;
}
validate21.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
export const validateFetchResult = validate101;
function validate101(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate101.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.fetch_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "fetch_id" },
        message: "must have required property '" + "fetch_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.topic_id === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "topic_id" },
        message: "must have required property '" + "topic_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.state === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "state" },
        message: "must have required property '" + "state" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.scope === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "scope" },
        message: "must have required property '" + "scope" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.window === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "window" },
        message: "must have required property '" + "window" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    if (data.columns === undefined) {
      const err5 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "columns" },
        message: "must have required property '" + "columns" + "'",
      };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
    }
    if (data.rows === undefined) {
      const err6 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "rows" },
        message: "must have required property '" + "rows" + "'",
      };
      if (vErrors === null) {
        vErrors = [err6];
      } else {
        vErrors.push(err6);
      }
      errors++;
    }
    if (data.checks === undefined) {
      const err7 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "checks" },
        message: "must have required property '" + "checks" + "'",
      };
      if (vErrors === null) {
        vErrors = [err7];
      } else {
        vErrors.push(err7);
      }
      errors++;
    }
    if (data.snapshot === undefined) {
      const err8 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "snapshot" },
        message: "must have required property '" + "snapshot" + "'",
      };
      if (vErrors === null) {
        vErrors = [err8];
      } else {
        vErrors.push(err8);
      }
      errors++;
    }
    if (data.items === undefined) {
      const err9 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "items" },
        message: "must have required property '" + "items" + "'",
      };
      if (vErrors === null) {
        vErrors = [err9];
      } else {
        vErrors.push(err9);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!func1.call(schema56.properties, key0)) {
        const err10 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.bucket_completeness !== undefined) {
      let data0 = data.bucket_completeness;
      if (typeof data0 !== "string") {
        const err11 = {
          instancePath: instancePath + "/bucket_completeness",
          schemaPath: "#/properties/bucket_completeness/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
      if (!(data0 === "complete" || data0 === "partial" || data0 === "unknown")) {
        const err12 = {
          instancePath: instancePath + "/bucket_completeness",
          schemaPath: "#/properties/bucket_completeness/enum",
          keyword: "enum",
          params: { allowedValues: schema56.properties.bucket_completeness.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.buckets !== undefined) {
      let data1 = data.buckets;
      if (Array.isArray(data1)) {
        const len0 = data1.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate39(data1[i0], {
              instancePath: instancePath + "/buckets/" + i0,
              parentData: data1,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate39.errors : vErrors.concat(validate39.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err13 = {
          instancePath: instancePath + "/buckets",
          schemaPath: "#/properties/buckets/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
    }
    if (data.checks !== undefined) {
      let data3 = data.checks;
      if (Array.isArray(data3)) {
        const len1 = data3.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate41(data3[i1], {
              instancePath: instancePath + "/checks/" + i1,
              parentData: data3,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate41.errors : vErrors.concat(validate41.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err14 = {
          instancePath: instancePath + "/checks",
          schemaPath: "#/properties/checks/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err14];
        } else {
          vErrors.push(err14);
        }
        errors++;
      }
    }
    if (data.columns !== undefined) {
      let data5 = data.columns;
      if (Array.isArray(data5)) {
        const len2 = data5.length;
        for (let i2 = 0; i2 < len2; i2++) {
          if (
            !validate43(data5[i2], {
              instancePath: instancePath + "/columns/" + i2,
              parentData: data5,
              parentDataProperty: i2,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate43.errors : vErrors.concat(validate43.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err15 = {
          instancePath: instancePath + "/columns",
          schemaPath: "#/properties/columns/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
      }
    }
    if (data.count !== undefined) {
      let data7 = data.count;
      const _errs14 = errors;
      let valid7 = false;
      const _errs15 = errors;
      if (data7 && typeof data7 == "object" && !Array.isArray(data7)) {
        if (data7.value === undefined) {
          const err16 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "value" },
            message: "must have required property '" + "value" + "'",
          };
          if (vErrors === null) {
            vErrors = [err16];
          } else {
            vErrors.push(err16);
          }
          errors++;
        }
        if (data7.relation === undefined) {
          const err17 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "relation" },
            message: "must have required property '" + "relation" + "'",
          };
          if (vErrors === null) {
            vErrors = [err17];
          } else {
            vErrors.push(err17);
          }
          errors++;
        }
        if (data7.scope === undefined) {
          const err18 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "scope" },
            message: "must have required property '" + "scope" + "'",
          };
          if (vErrors === null) {
            vErrors = [err18];
          } else {
            vErrors.push(err18);
          }
          errors++;
        }
        if (data7.computed_by === undefined) {
          const err19 = {
            instancePath: instancePath + "/count",
            schemaPath: "#/$defs/Count/required",
            keyword: "required",
            params: { missingProperty: "computed_by" },
            message: "must have required property '" + "computed_by" + "'",
          };
          if (vErrors === null) {
            vErrors = [err19];
          } else {
            vErrors.push(err19);
          }
          errors++;
        }
        for (const key1 in data7) {
          if (
            !(
              key1 === "approximate" ||
              key1 === "computed_by" ||
              key1 === "relation" ||
              key1 === "scope" ||
              key1 === "value"
            )
          ) {
            const err20 = {
              instancePath: instancePath + "/count",
              schemaPath: "#/$defs/Count/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err20];
            } else {
              vErrors.push(err20);
            }
            errors++;
          }
        }
        if (data7.approximate !== undefined) {
          if (typeof data7.approximate !== "boolean") {
            const err21 = {
              instancePath: instancePath + "/count/approximate",
              schemaPath: "#/$defs/Count/properties/approximate/type",
              keyword: "type",
              params: { type: "boolean" },
              message: "must be boolean",
            };
            if (vErrors === null) {
              vErrors = [err21];
            } else {
              vErrors.push(err21);
            }
            errors++;
          }
        }
        if (data7.computed_by !== undefined) {
          let data9 = data7.computed_by;
          if (typeof data9 !== "string") {
            const err22 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err22];
            } else {
              vErrors.push(err22);
            }
            errors++;
          }
          if ("indexer" !== data9) {
            const err23 = {
              instancePath: instancePath + "/count/computed_by",
              schemaPath: "#/$defs/Count/properties/computed_by/const",
              keyword: "const",
              params: { allowedValue: "indexer" },
              message: "must be equal to constant",
            };
            if (vErrors === null) {
              vErrors = [err23];
            } else {
              vErrors.push(err23);
            }
            errors++;
          }
        }
        if (data7.relation !== undefined) {
          let data10 = data7.relation;
          if (typeof data10 !== "string") {
            const err24 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
          }
          if (!(data10 === "eq" || data10 === "gte")) {
            const err25 = {
              instancePath: instancePath + "/count/relation",
              schemaPath: "#/$defs/Count/properties/relation/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.relation.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err25];
            } else {
              vErrors.push(err25);
            }
            errors++;
          }
        }
        if (data7.scope !== undefined) {
          let data11 = data7.scope;
          if (typeof data11 !== "string") {
            const err26 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err26];
            } else {
              vErrors.push(err26);
            }
            errors++;
          }
          if (!(data11 === "matching_visible_records" || data11 === "bucket_visible_records")) {
            const err27 = {
              instancePath: instancePath + "/count/scope",
              schemaPath: "#/$defs/Count/properties/scope/enum",
              keyword: "enum",
              params: { allowedValues: schema58.properties.scope.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err27];
            } else {
              vErrors.push(err27);
            }
            errors++;
          }
        }
        if (data7.value !== undefined) {
          let data12 = data7.value;
          if (!(typeof data12 == "number" && !(data12 % 1) && !isNaN(data12) && isFinite(data12))) {
            const err28 = {
              instancePath: instancePath + "/count/value",
              schemaPath: "#/$defs/Count/properties/value/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err28];
            } else {
              vErrors.push(err28);
            }
            errors++;
          }
          if (typeof data12 == "number" && isFinite(data12)) {
            if (data12 < 0 || isNaN(data12)) {
              const err29 = {
                instancePath: instancePath + "/count/value",
                schemaPath: "#/$defs/Count/properties/value/minimum",
                keyword: "minimum",
                params: { comparison: ">=", limit: 0 },
                message: "must be >= 0",
              };
              if (vErrors === null) {
                vErrors = [err29];
              } else {
                vErrors.push(err29);
              }
              errors++;
            }
          }
        }
      } else {
        const err30 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/$defs/Count/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err30];
        } else {
          vErrors.push(err30);
        }
        errors++;
      }
      var _valid0 = _errs15 === errors;
      valid7 = valid7 || _valid0;
      const _errs29 = errors;
      if (data7 !== null) {
        const err31 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err31];
        } else {
          vErrors.push(err31);
        }
        errors++;
      }
      var _valid0 = _errs29 === errors;
      valid7 = valid7 || _valid0;
      if (!valid7) {
        const err32 = {
          instancePath: instancePath + "/count",
          schemaPath: "#/properties/count/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err32];
        } else {
          vErrors.push(err32);
        }
        errors++;
      } else {
        errors = _errs14;
        if (vErrors !== null) {
          if (_errs14) {
            vErrors.length = _errs14;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.empty_proof !== undefined) {
      let data13 = data.empty_proof;
      const _errs32 = errors;
      let valid10 = false;
      const _errs33 = errors;
      if (
        !validate45(data13, {
          instancePath: instancePath + "/empty_proof",
          parentData: data,
          parentDataProperty: "empty_proof",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate45.errors : vErrors.concat(validate45.errors);
        errors = vErrors.length;
      }
      var _valid1 = _errs33 === errors;
      valid10 = valid10 || _valid1;
      const _errs34 = errors;
      if (data13 !== null) {
        const err33 = {
          instancePath: instancePath + "/empty_proof",
          schemaPath: "#/properties/empty_proof/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err33];
        } else {
          vErrors.push(err33);
        }
        errors++;
      }
      var _valid1 = _errs34 === errors;
      valid10 = valid10 || _valid1;
      if (!valid10) {
        const err34 = {
          instancePath: instancePath + "/empty_proof",
          schemaPath: "#/properties/empty_proof/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err34];
        } else {
          vErrors.push(err34);
        }
        errors++;
      } else {
        errors = _errs32;
        if (vErrors !== null) {
          if (_errs32) {
            vErrors.length = _errs32;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.error !== undefined) {
      let data14 = data.error;
      const _errs37 = errors;
      let valid11 = false;
      const _errs38 = errors;
      if (
        !validate79(data14, {
          instancePath: instancePath + "/error",
          parentData: data,
          parentDataProperty: "error",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate79.errors : vErrors.concat(validate79.errors);
        errors = vErrors.length;
      }
      var _valid2 = _errs38 === errors;
      valid11 = valid11 || _valid2;
      const _errs39 = errors;
      if (data14 !== null) {
        const err35 = {
          instancePath: instancePath + "/error",
          schemaPath: "#/properties/error/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err35];
        } else {
          vErrors.push(err35);
        }
        errors++;
      }
      var _valid2 = _errs39 === errors;
      valid11 = valid11 || _valid2;
      if (!valid11) {
        const err36 = {
          instancePath: instancePath + "/error",
          schemaPath: "#/properties/error/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err36];
        } else {
          vErrors.push(err36);
        }
        errors++;
      } else {
        errors = _errs37;
        if (vErrors !== null) {
          if (_errs37) {
            vErrors.length = _errs37;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.fetch_id !== undefined) {
      let data15 = data.fetch_id;
      if (typeof data15 === "string") {
        if (!pattern4.test(data15)) {
          const err37 = {
            instancePath: instancePath + "/fetch_id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err37];
          } else {
            vErrors.push(err37);
          }
          errors++;
        }
      } else {
        const err38 = {
          instancePath: instancePath + "/fetch_id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err38];
        } else {
          vErrors.push(err38);
        }
        errors++;
      }
    }
    if (data.items !== undefined) {
      let data16 = data.items;
      if (Array.isArray(data16)) {
        const len3 = data16.length;
        for (let i3 = 0; i3 < len3; i3++) {
          if (
            !validate50(data16[i3], {
              instancePath: instancePath + "/items/" + i3,
              parentData: data16,
              parentDataProperty: i3,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate50.errors : vErrors.concat(validate50.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err39 = {
          instancePath: instancePath + "/items",
          schemaPath: "#/properties/items/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err39];
        } else {
          vErrors.push(err39);
        }
        errors++;
      }
    }
    if (data.message !== undefined) {
      let data18 = data.message;
      const _errs48 = errors;
      let valid15 = false;
      const _errs49 = errors;
      if (typeof data18 !== "string") {
        const err40 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err40];
        } else {
          vErrors.push(err40);
        }
        errors++;
      }
      var _valid3 = _errs49 === errors;
      valid15 = valid15 || _valid3;
      const _errs51 = errors;
      if (data18 !== null) {
        const err41 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err41];
        } else {
          vErrors.push(err41);
        }
        errors++;
      }
      var _valid3 = _errs51 === errors;
      valid15 = valid15 || _valid3;
      if (!valid15) {
        const err42 = {
          instancePath: instancePath + "/message",
          schemaPath: "#/properties/message/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err42];
        } else {
          vErrors.push(err42);
        }
        errors++;
      } else {
        errors = _errs48;
        if (vErrors !== null) {
          if (_errs48) {
            vErrors.length = _errs48;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.next_cursor !== undefined) {
      let data19 = data.next_cursor;
      const _errs54 = errors;
      let valid16 = false;
      const _errs55 = errors;
      if (typeof data19 !== "string") {
        const err43 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err43];
        } else {
          vErrors.push(err43);
        }
        errors++;
      }
      var _valid4 = _errs55 === errors;
      valid16 = valid16 || _valid4;
      const _errs57 = errors;
      if (data19 !== null) {
        const err44 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err44];
        } else {
          vErrors.push(err44);
        }
        errors++;
      }
      var _valid4 = _errs57 === errors;
      valid16 = valid16 || _valid4;
      if (!valid16) {
        const err45 = {
          instancePath: instancePath + "/next_cursor",
          schemaPath: "#/properties/next_cursor/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err45];
        } else {
          vErrors.push(err45);
        }
        errors++;
      } else {
        errors = _errs54;
        if (vErrors !== null) {
          if (_errs54) {
            vErrors.length = _errs54;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.rows !== undefined) {
      let data20 = data.rows;
      if (Array.isArray(data20)) {
        const len4 = data20.length;
        for (let i4 = 0; i4 < len4; i4++) {
          if (
            !validate82(data20[i4], {
              instancePath: instancePath + "/rows/" + i4,
              parentData: data20,
              parentDataProperty: i4,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err46 = {
          instancePath: instancePath + "/rows",
          schemaPath: "#/properties/rows/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err46];
        } else {
          vErrors.push(err46);
        }
        errors++;
      }
    }
    if (data.scope !== undefined) {
      if (
        !validate85(data.scope, {
          instancePath: instancePath + "/scope",
          parentData: data,
          parentDataProperty: "scope",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate85.errors : vErrors.concat(validate85.errors);
        errors = vErrors.length;
      }
    }
    if (data.snapshot !== undefined) {
      if (
        !validate51(data.snapshot, {
          instancePath: instancePath + "/snapshot",
          parentData: data,
          parentDataProperty: "snapshot",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate51.errors : vErrors.concat(validate51.errors);
        errors = vErrors.length;
      }
    }
    if (data.snapshot_at !== undefined) {
      let data24 = data.snapshot_at;
      const _errs65 = errors;
      let valid19 = false;
      const _errs66 = errors;
      if (typeof data24 === "string") {
        if (!formats4.validate(data24)) {
          const err47 = {
            instancePath: instancePath + "/snapshot_at",
            schemaPath: "#/$defs/UTCDateTime/format",
            keyword: "format",
            params: { format: "date-time" },
            message: 'must match format "' + "date-time" + '"',
          };
          if (vErrors === null) {
            vErrors = [err47];
          } else {
            vErrors.push(err47);
          }
          errors++;
        }
      } else {
        const err48 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/$defs/UTCDateTime/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err48];
        } else {
          vErrors.push(err48);
        }
        errors++;
      }
      var _valid5 = _errs66 === errors;
      valid19 = valid19 || _valid5;
      const _errs69 = errors;
      if (data24 !== null) {
        const err49 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/properties/snapshot_at/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err49];
        } else {
          vErrors.push(err49);
        }
        errors++;
      }
      var _valid5 = _errs69 === errors;
      valid19 = valid19 || _valid5;
      if (!valid19) {
        const err50 = {
          instancePath: instancePath + "/snapshot_at",
          schemaPath: "#/properties/snapshot_at/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err50];
        } else {
          vErrors.push(err50);
        }
        errors++;
      } else {
        errors = _errs65;
        if (vErrors !== null) {
          if (_errs65) {
            vErrors.length = _errs65;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.state !== undefined) {
      let data25 = data.state;
      if (typeof data25 !== "string") {
        const err51 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/FetchState/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err51];
        } else {
          vErrors.push(err51);
        }
        errors++;
      }
      if (
        !(
          data25 === "rows" ||
          data25 === "empty" ||
          data25 === "filtered" ||
          data25 === "denied" ||
          data25 === "unavailable"
        )
      ) {
        const err52 = {
          instancePath: instancePath + "/state",
          schemaPath: "#/$defs/FetchState/enum",
          keyword: "enum",
          params: { allowedValues: schema138.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err52];
        } else {
          vErrors.push(err52);
        }
        errors++;
      }
    }
    if (data.topic_id !== undefined) {
      if (
        !validate24(data.topic_id, {
          instancePath: instancePath + "/topic_id",
          parentData: data,
          parentDataProperty: "topic_id",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate24.errors : vErrors.concat(validate24.errors);
        errors = vErrors.length;
      }
    }
    if (data.window !== undefined) {
      if (
        !validate58(data.window, {
          instancePath: instancePath + "/window",
          parentData: data,
          parentDataProperty: "window",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate58.errors : vErrors.concat(validate58.errors);
        errors = vErrors.length;
      }
    }
  } else {
    const err53 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err53];
    } else {
      vErrors.push(err53);
    }
    errors++;
  }
  validate101.errors = vErrors;
  return errors === 0;
}
validate101.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
export const validateBootstrapResponse = validate113;
const schema156 = {
  additionalProperties: false,
  properties: {
    csrf_token: {
      anyOf: [{ type: "string" }, { type: "null" }],
      default: null,
      title: "Csrf Token",
    },
    limits: { $ref: "#/$defs/PublicLimits" },
    mode: { enum: ["fixture", "live"], title: "Mode", type: "string" },
    models: { items: { $ref: "#/$defs/ModelCapabilityPublic" }, title: "Models", type: "array" },
    provenance: { $ref: "#/$defs/BuildProvenance" },
    schema_version: { const: "1", default: "1", title: "Schema Version", type: "string" },
    sites: { items: { $ref: "#/$defs/SitePublic" }, title: "Sites", type: "array" },
  },
  required: ["sites", "models", "provenance", "mode", "limits"],
  title: "BootstrapResponse",
  type: "object",
};
const schema157 = {
  additionalProperties: false,
  properties: {
    page_size: { exclusiveMinimum: 0, title: "Page Size", type: "integer" },
    plan_bytes: { exclusiveMinimum: 0, title: "Plan Bytes", type: "integer" },
    question_bytes: { exclusiveMinimum: 0, title: "Question Bytes", type: "integer" },
    request_bytes: { exclusiveMinimum: 0, title: "Request Bytes", type: "integer" },
    window_days: { exclusiveMinimum: 0, title: "Window Days", type: "integer" },
  },
  required: ["question_bytes", "page_size", "window_days", "request_bytes", "plan_bytes"],
  title: "PublicLimits",
  type: "object",
};
const schema158 = {
  additionalProperties: false,
  properties: {
    context_tokens: { exclusiveMinimum: 0, title: "Context Tokens", type: "integer" },
    efforts: { items: { $ref: "#/$defs/Effort" }, title: "Efforts", type: "array" },
    id: { title: "Id", type: "string" },
    label: { title: "Label", type: "string" },
    max_output_tokens: { exclusiveMinimum: 0, title: "Max Output Tokens", type: "integer" },
  },
  required: ["id", "label", "efforts", "context_tokens", "max_output_tokens"],
  title: "ModelCapabilityPublic",
  type: "object",
};
function validate114(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate114.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "id" },
        message: "must have required property '" + "id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.label === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "label" },
        message: "must have required property '" + "label" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.efforts === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "efforts" },
        message: "must have required property '" + "efforts" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.context_tokens === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "context_tokens" },
        message: "must have required property '" + "context_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.max_output_tokens === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "max_output_tokens" },
        message: "must have required property '" + "max_output_tokens" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "context_tokens" ||
          key0 === "efforts" ||
          key0 === "id" ||
          key0 === "label" ||
          key0 === "max_output_tokens"
        )
      ) {
        const err5 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.context_tokens !== undefined) {
      let data0 = data.context_tokens;
      if (!(typeof data0 == "number" && !(data0 % 1) && !isNaN(data0) && isFinite(data0))) {
        const err6 = {
          instancePath: instancePath + "/context_tokens",
          schemaPath: "#/properties/context_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      if (typeof data0 == "number" && isFinite(data0)) {
        if (data0 <= 0 || isNaN(data0)) {
          const err7 = {
            instancePath: instancePath + "/context_tokens",
            schemaPath: "#/properties/context_tokens/exclusiveMinimum",
            keyword: "exclusiveMinimum",
            params: { comparison: ">", limit: 0 },
            message: "must be > 0",
          };
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      }
    }
    if (data.efforts !== undefined) {
      let data1 = data.efforts;
      if (Array.isArray(data1)) {
        const len0 = data1.length;
        for (let i0 = 0; i0 < len0; i0++) {
          let data2 = data1[i0];
          if (typeof data2 !== "string") {
            const err8 = {
              instancePath: instancePath + "/efforts/" + i0,
              schemaPath: "#/$defs/Effort/type",
              keyword: "type",
              params: { type: "string" },
              message: "must be string",
            };
            if (vErrors === null) {
              vErrors = [err8];
            } else {
              vErrors.push(err8);
            }
            errors++;
          }
          if (
            !(
              data2 === "low" ||
              data2 === "medium" ||
              data2 === "high" ||
              data2 === "xhigh" ||
              data2 === "max"
            )
          ) {
            const err9 = {
              instancePath: instancePath + "/efforts/" + i0,
              schemaPath: "#/$defs/Effort/enum",
              keyword: "enum",
              params: { allowedValues: schema47.enum },
              message: "must be equal to one of the allowed values",
            };
            if (vErrors === null) {
              vErrors = [err9];
            } else {
              vErrors.push(err9);
            }
            errors++;
          }
        }
      } else {
        const err10 = {
          instancePath: instancePath + "/efforts",
          schemaPath: "#/properties/efforts/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err10];
        } else {
          vErrors.push(err10);
        }
        errors++;
      }
    }
    if (data.id !== undefined) {
      if (typeof data.id !== "string") {
        const err11 = {
          instancePath: instancePath + "/id",
          schemaPath: "#/properties/id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err11];
        } else {
          vErrors.push(err11);
        }
        errors++;
      }
    }
    if (data.label !== undefined) {
      if (typeof data.label !== "string") {
        const err12 = {
          instancePath: instancePath + "/label",
          schemaPath: "#/properties/label/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err12];
        } else {
          vErrors.push(err12);
        }
        errors++;
      }
    }
    if (data.max_output_tokens !== undefined) {
      let data5 = data.max_output_tokens;
      if (!(typeof data5 == "number" && !(data5 % 1) && !isNaN(data5) && isFinite(data5))) {
        const err13 = {
          instancePath: instancePath + "/max_output_tokens",
          schemaPath: "#/properties/max_output_tokens/type",
          keyword: "type",
          params: { type: "integer" },
          message: "must be integer",
        };
        if (vErrors === null) {
          vErrors = [err13];
        } else {
          vErrors.push(err13);
        }
        errors++;
      }
      if (typeof data5 == "number" && isFinite(data5)) {
        if (data5 <= 0 || isNaN(data5)) {
          const err14 = {
            instancePath: instancePath + "/max_output_tokens",
            schemaPath: "#/properties/max_output_tokens/exclusiveMinimum",
            keyword: "exclusiveMinimum",
            params: { comparison: ">", limit: 0 },
            message: "must be > 0",
          };
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        }
      }
    }
  } else {
    const err15 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err15];
    } else {
      vErrors.push(err15);
    }
    errors++;
  }
  validate114.errors = vErrors;
  return errors === 0;
}
validate114.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
const schema160 = {
  additionalProperties: false,
  properties: { id: { $ref: "#/$defs/ContentId" }, label: { title: "Label", type: "string" } },
  required: ["id", "label"],
  title: "SitePublic",
  type: "object",
};
function validate117(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate117.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "id" },
        message: "must have required property '" + "id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.label === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "label" },
        message: "must have required property '" + "label" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "id" || key0 === "label")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.id !== undefined) {
      let data0 = data.id;
      if (typeof data0 === "string") {
        if (!pattern4.test(data0)) {
          const err3 = {
            instancePath: instancePath + "/id",
            schemaPath: "#/$defs/ContentId/pattern",
            keyword: "pattern",
            params: { pattern: "^[a-z][a-z0-9_-]{0,63}$" },
            message: 'must match pattern "' + "^[a-z][a-z0-9_-]{0,63}$" + '"',
          };
          if (vErrors === null) {
            vErrors = [err3];
          } else {
            vErrors.push(err3);
          }
          errors++;
        }
      } else {
        const err4 = {
          instancePath: instancePath + "/id",
          schemaPath: "#/$defs/ContentId/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.label !== undefined) {
      if (typeof data.label !== "string") {
        const err5 = {
          instancePath: instancePath + "/label",
          schemaPath: "#/properties/label/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
  } else {
    const err6 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err6];
    } else {
      vErrors.push(err6);
    }
    errors++;
  }
  validate117.errors = vErrors;
  return errors === 0;
}
validate117.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
function validate113(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate113.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.sites === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "sites" },
        message: "must have required property '" + "sites" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.models === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "models" },
        message: "must have required property '" + "models" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    if (data.provenance === undefined) {
      const err2 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "provenance" },
        message: "must have required property '" + "provenance" + "'",
      };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    }
    if (data.mode === undefined) {
      const err3 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "mode" },
        message: "must have required property '" + "mode" + "'",
      };
      if (vErrors === null) {
        vErrors = [err3];
      } else {
        vErrors.push(err3);
      }
      errors++;
    }
    if (data.limits === undefined) {
      const err4 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "limits" },
        message: "must have required property '" + "limits" + "'",
      };
      if (vErrors === null) {
        vErrors = [err4];
      } else {
        vErrors.push(err4);
      }
      errors++;
    }
    for (const key0 in data) {
      if (
        !(
          key0 === "csrf_token" ||
          key0 === "limits" ||
          key0 === "mode" ||
          key0 === "models" ||
          key0 === "provenance" ||
          key0 === "schema_version" ||
          key0 === "sites"
        )
      ) {
        const err5 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
    }
    if (data.csrf_token !== undefined) {
      let data0 = data.csrf_token;
      const _errs3 = errors;
      let valid1 = false;
      const _errs4 = errors;
      if (typeof data0 !== "string") {
        const err6 = {
          instancePath: instancePath + "/csrf_token",
          schemaPath: "#/properties/csrf_token/anyOf/0/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
      var _valid0 = _errs4 === errors;
      valid1 = valid1 || _valid0;
      const _errs6 = errors;
      if (data0 !== null) {
        const err7 = {
          instancePath: instancePath + "/csrf_token",
          schemaPath: "#/properties/csrf_token/anyOf/1/type",
          keyword: "type",
          params: { type: "null" },
          message: "must be null",
        };
        if (vErrors === null) {
          vErrors = [err7];
        } else {
          vErrors.push(err7);
        }
        errors++;
      }
      var _valid0 = _errs6 === errors;
      valid1 = valid1 || _valid0;
      if (!valid1) {
        const err8 = {
          instancePath: instancePath + "/csrf_token",
          schemaPath: "#/properties/csrf_token/anyOf",
          keyword: "anyOf",
          params: {},
          message: "must match a schema in anyOf",
        };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      } else {
        errors = _errs3;
        if (vErrors !== null) {
          if (_errs3) {
            vErrors.length = _errs3;
          } else {
            vErrors = null;
          }
        }
      }
    }
    if (data.limits !== undefined) {
      let data1 = data.limits;
      if (data1 && typeof data1 == "object" && !Array.isArray(data1)) {
        if (data1.question_bytes === undefined) {
          const err9 = {
            instancePath: instancePath + "/limits",
            schemaPath: "#/$defs/PublicLimits/required",
            keyword: "required",
            params: { missingProperty: "question_bytes" },
            message: "must have required property '" + "question_bytes" + "'",
          };
          if (vErrors === null) {
            vErrors = [err9];
          } else {
            vErrors.push(err9);
          }
          errors++;
        }
        if (data1.page_size === undefined) {
          const err10 = {
            instancePath: instancePath + "/limits",
            schemaPath: "#/$defs/PublicLimits/required",
            keyword: "required",
            params: { missingProperty: "page_size" },
            message: "must have required property '" + "page_size" + "'",
          };
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        }
        if (data1.window_days === undefined) {
          const err11 = {
            instancePath: instancePath + "/limits",
            schemaPath: "#/$defs/PublicLimits/required",
            keyword: "required",
            params: { missingProperty: "window_days" },
            message: "must have required property '" + "window_days" + "'",
          };
          if (vErrors === null) {
            vErrors = [err11];
          } else {
            vErrors.push(err11);
          }
          errors++;
        }
        if (data1.request_bytes === undefined) {
          const err12 = {
            instancePath: instancePath + "/limits",
            schemaPath: "#/$defs/PublicLimits/required",
            keyword: "required",
            params: { missingProperty: "request_bytes" },
            message: "must have required property '" + "request_bytes" + "'",
          };
          if (vErrors === null) {
            vErrors = [err12];
          } else {
            vErrors.push(err12);
          }
          errors++;
        }
        if (data1.plan_bytes === undefined) {
          const err13 = {
            instancePath: instancePath + "/limits",
            schemaPath: "#/$defs/PublicLimits/required",
            keyword: "required",
            params: { missingProperty: "plan_bytes" },
            message: "must have required property '" + "plan_bytes" + "'",
          };
          if (vErrors === null) {
            vErrors = [err13];
          } else {
            vErrors.push(err13);
          }
          errors++;
        }
        for (const key1 in data1) {
          if (
            !(
              key1 === "page_size" ||
              key1 === "plan_bytes" ||
              key1 === "question_bytes" ||
              key1 === "request_bytes" ||
              key1 === "window_days"
            )
          ) {
            const err14 = {
              instancePath: instancePath + "/limits",
              schemaPath: "#/$defs/PublicLimits/additionalProperties",
              keyword: "additionalProperties",
              params: { additionalProperty: key1 },
              message: "must NOT have additional properties",
            };
            if (vErrors === null) {
              vErrors = [err14];
            } else {
              vErrors.push(err14);
            }
            errors++;
          }
        }
        if (data1.page_size !== undefined) {
          let data2 = data1.page_size;
          if (!(typeof data2 == "number" && !(data2 % 1) && !isNaN(data2) && isFinite(data2))) {
            const err15 = {
              instancePath: instancePath + "/limits/page_size",
              schemaPath: "#/$defs/PublicLimits/properties/page_size/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err15];
            } else {
              vErrors.push(err15);
            }
            errors++;
          }
          if (typeof data2 == "number" && isFinite(data2)) {
            if (data2 <= 0 || isNaN(data2)) {
              const err16 = {
                instancePath: instancePath + "/limits/page_size",
                schemaPath: "#/$defs/PublicLimits/properties/page_size/exclusiveMinimum",
                keyword: "exclusiveMinimum",
                params: { comparison: ">", limit: 0 },
                message: "must be > 0",
              };
              if (vErrors === null) {
                vErrors = [err16];
              } else {
                vErrors.push(err16);
              }
              errors++;
            }
          }
        }
        if (data1.plan_bytes !== undefined) {
          let data3 = data1.plan_bytes;
          if (!(typeof data3 == "number" && !(data3 % 1) && !isNaN(data3) && isFinite(data3))) {
            const err17 = {
              instancePath: instancePath + "/limits/plan_bytes",
              schemaPath: "#/$defs/PublicLimits/properties/plan_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err17];
            } else {
              vErrors.push(err17);
            }
            errors++;
          }
          if (typeof data3 == "number" && isFinite(data3)) {
            if (data3 <= 0 || isNaN(data3)) {
              const err18 = {
                instancePath: instancePath + "/limits/plan_bytes",
                schemaPath: "#/$defs/PublicLimits/properties/plan_bytes/exclusiveMinimum",
                keyword: "exclusiveMinimum",
                params: { comparison: ">", limit: 0 },
                message: "must be > 0",
              };
              if (vErrors === null) {
                vErrors = [err18];
              } else {
                vErrors.push(err18);
              }
              errors++;
            }
          }
        }
        if (data1.question_bytes !== undefined) {
          let data4 = data1.question_bytes;
          if (!(typeof data4 == "number" && !(data4 % 1) && !isNaN(data4) && isFinite(data4))) {
            const err19 = {
              instancePath: instancePath + "/limits/question_bytes",
              schemaPath: "#/$defs/PublicLimits/properties/question_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err19];
            } else {
              vErrors.push(err19);
            }
            errors++;
          }
          if (typeof data4 == "number" && isFinite(data4)) {
            if (data4 <= 0 || isNaN(data4)) {
              const err20 = {
                instancePath: instancePath + "/limits/question_bytes",
                schemaPath: "#/$defs/PublicLimits/properties/question_bytes/exclusiveMinimum",
                keyword: "exclusiveMinimum",
                params: { comparison: ">", limit: 0 },
                message: "must be > 0",
              };
              if (vErrors === null) {
                vErrors = [err20];
              } else {
                vErrors.push(err20);
              }
              errors++;
            }
          }
        }
        if (data1.request_bytes !== undefined) {
          let data5 = data1.request_bytes;
          if (!(typeof data5 == "number" && !(data5 % 1) && !isNaN(data5) && isFinite(data5))) {
            const err21 = {
              instancePath: instancePath + "/limits/request_bytes",
              schemaPath: "#/$defs/PublicLimits/properties/request_bytes/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err21];
            } else {
              vErrors.push(err21);
            }
            errors++;
          }
          if (typeof data5 == "number" && isFinite(data5)) {
            if (data5 <= 0 || isNaN(data5)) {
              const err22 = {
                instancePath: instancePath + "/limits/request_bytes",
                schemaPath: "#/$defs/PublicLimits/properties/request_bytes/exclusiveMinimum",
                keyword: "exclusiveMinimum",
                params: { comparison: ">", limit: 0 },
                message: "must be > 0",
              };
              if (vErrors === null) {
                vErrors = [err22];
              } else {
                vErrors.push(err22);
              }
              errors++;
            }
          }
        }
        if (data1.window_days !== undefined) {
          let data6 = data1.window_days;
          if (!(typeof data6 == "number" && !(data6 % 1) && !isNaN(data6) && isFinite(data6))) {
            const err23 = {
              instancePath: instancePath + "/limits/window_days",
              schemaPath: "#/$defs/PublicLimits/properties/window_days/type",
              keyword: "type",
              params: { type: "integer" },
              message: "must be integer",
            };
            if (vErrors === null) {
              vErrors = [err23];
            } else {
              vErrors.push(err23);
            }
            errors++;
          }
          if (typeof data6 == "number" && isFinite(data6)) {
            if (data6 <= 0 || isNaN(data6)) {
              const err24 = {
                instancePath: instancePath + "/limits/window_days",
                schemaPath: "#/$defs/PublicLimits/properties/window_days/exclusiveMinimum",
                keyword: "exclusiveMinimum",
                params: { comparison: ">", limit: 0 },
                message: "must be > 0",
              };
              if (vErrors === null) {
                vErrors = [err24];
              } else {
                vErrors.push(err24);
              }
              errors++;
            }
          }
        }
      } else {
        const err25 = {
          instancePath: instancePath + "/limits",
          schemaPath: "#/$defs/PublicLimits/type",
          keyword: "type",
          params: { type: "object" },
          message: "must be object",
        };
        if (vErrors === null) {
          vErrors = [err25];
        } else {
          vErrors.push(err25);
        }
        errors++;
      }
    }
    if (data.mode !== undefined) {
      let data7 = data.mode;
      if (typeof data7 !== "string") {
        const err26 = {
          instancePath: instancePath + "/mode",
          schemaPath: "#/properties/mode/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err26];
        } else {
          vErrors.push(err26);
        }
        errors++;
      }
      if (!(data7 === "fixture" || data7 === "live")) {
        const err27 = {
          instancePath: instancePath + "/mode",
          schemaPath: "#/properties/mode/enum",
          keyword: "enum",
          params: { allowedValues: schema156.properties.mode.enum },
          message: "must be equal to one of the allowed values",
        };
        if (vErrors === null) {
          vErrors = [err27];
        } else {
          vErrors.push(err27);
        }
        errors++;
      }
    }
    if (data.models !== undefined) {
      let data8 = data.models;
      if (Array.isArray(data8)) {
        const len0 = data8.length;
        for (let i0 = 0; i0 < len0; i0++) {
          if (
            !validate114(data8[i0], {
              instancePath: instancePath + "/models/" + i0,
              parentData: data8,
              parentDataProperty: i0,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate114.errors : vErrors.concat(validate114.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err28 = {
          instancePath: instancePath + "/models",
          schemaPath: "#/properties/models/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err28];
        } else {
          vErrors.push(err28);
        }
        errors++;
      }
    }
    if (data.provenance !== undefined) {
      if (
        !validate99(data.provenance, {
          instancePath: instancePath + "/provenance",
          parentData: data,
          parentDataProperty: "provenance",
          rootData,
          dynamicAnchors,
        })
      ) {
        vErrors = vErrors === null ? validate99.errors : vErrors.concat(validate99.errors);
        errors = vErrors.length;
      }
    }
    if (data.schema_version !== undefined) {
      let data11 = data.schema_version;
      if (typeof data11 !== "string") {
        const err29 = {
          instancePath: instancePath + "/schema_version",
          schemaPath: "#/properties/schema_version/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err29];
        } else {
          vErrors.push(err29);
        }
        errors++;
      }
      if ("1" !== data11) {
        const err30 = {
          instancePath: instancePath + "/schema_version",
          schemaPath: "#/properties/schema_version/const",
          keyword: "const",
          params: { allowedValue: "1" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err30];
        } else {
          vErrors.push(err30);
        }
        errors++;
      }
    }
    if (data.sites !== undefined) {
      let data12 = data.sites;
      if (Array.isArray(data12)) {
        const len1 = data12.length;
        for (let i1 = 0; i1 < len1; i1++) {
          if (
            !validate117(data12[i1], {
              instancePath: instancePath + "/sites/" + i1,
              parentData: data12,
              parentDataProperty: i1,
              rootData,
              dynamicAnchors,
            })
          ) {
            vErrors = vErrors === null ? validate117.errors : vErrors.concat(validate117.errors);
            errors = vErrors.length;
          }
        }
      } else {
        const err31 = {
          instancePath: instancePath + "/sites",
          schemaPath: "#/properties/sites/type",
          keyword: "type",
          params: { type: "array" },
          message: "must be array",
        };
        if (vErrors === null) {
          vErrors = [err31];
        } else {
          vErrors.push(err31);
        }
        errors++;
      }
    }
  } else {
    const err32 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err32];
    } else {
      vErrors.push(err32);
    }
    errors++;
  }
  validate113.errors = vErrors;
  return errors === 0;
}
validate113.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
export const validateFeedbackQueued = validate119;
const schema162 = {
  additionalProperties: false,
  properties: {
    feedback_id: { format: "uuid", title: "Feedback Id", type: "string" },
    status: { const: "queued", title: "Status", type: "string" },
  },
  required: ["feedback_id", "status"],
  title: "FeedbackQueued",
  type: "object",
};
function validate119(
  data,
  { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {},
) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate119.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = undefined;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = undefined;
  }
  if (data && typeof data == "object" && !Array.isArray(data)) {
    if (data.feedback_id === undefined) {
      const err0 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "feedback_id" },
        message: "must have required property '" + "feedback_id" + "'",
      };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    }
    if (data.status === undefined) {
      const err1 = {
        instancePath,
        schemaPath: "#/required",
        keyword: "required",
        params: { missingProperty: "status" },
        message: "must have required property '" + "status" + "'",
      };
      if (vErrors === null) {
        vErrors = [err1];
      } else {
        vErrors.push(err1);
      }
      errors++;
    }
    for (const key0 in data) {
      if (!(key0 === "feedback_id" || key0 === "status")) {
        const err2 = {
          instancePath,
          schemaPath: "#/additionalProperties",
          keyword: "additionalProperties",
          params: { additionalProperty: key0 },
          message: "must NOT have additional properties",
        };
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    if (data.feedback_id !== undefined) {
      let data0 = data.feedback_id;
      if (typeof data0 === "string") {
        if (!formats2.test(data0)) {
          const err3 = {
            instancePath: instancePath + "/feedback_id",
            schemaPath: "#/properties/feedback_id/format",
            keyword: "format",
            params: { format: "uuid" },
            message: 'must match format "' + "uuid" + '"',
          };
          if (vErrors === null) {
            vErrors = [err3];
          } else {
            vErrors.push(err3);
          }
          errors++;
        }
      } else {
        const err4 = {
          instancePath: instancePath + "/feedback_id",
          schemaPath: "#/properties/feedback_id/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      }
    }
    if (data.status !== undefined) {
      let data1 = data.status;
      if (typeof data1 !== "string") {
        const err5 = {
          instancePath: instancePath + "/status",
          schemaPath: "#/properties/status/type",
          keyword: "type",
          params: { type: "string" },
          message: "must be string",
        };
        if (vErrors === null) {
          vErrors = [err5];
        } else {
          vErrors.push(err5);
        }
        errors++;
      }
      if ("queued" !== data1) {
        const err6 = {
          instancePath: instancePath + "/status",
          schemaPath: "#/properties/status/const",
          keyword: "const",
          params: { allowedValue: "queued" },
          message: "must be equal to constant",
        };
        if (vErrors === null) {
          vErrors = [err6];
        } else {
          vErrors.push(err6);
        }
        errors++;
      }
    }
  } else {
    const err7 = {
      instancePath,
      schemaPath: "#/type",
      keyword: "type",
      params: { type: "object" },
      message: "must be object",
    };
    if (vErrors === null) {
      vErrors = [err7];
    } else {
      vErrors.push(err7);
    }
    errors++;
  }
  validate119.errors = vErrors;
  return errors === 0;
}
validate119.evaluated = { props: true, dynamicProps: false, dynamicItems: false };
