const dbName = "yara_db";
const targetDb = db.getSiblingDB(dbName);

// Crear colecciones
targetDb.createCollection("rules");
// Índices para tags y estado
targetDb.rules.createIndex({ tags: 1 });
targetDb.rules.createIndex({ enabled: 1 });

// (Opcional) regla inicial de prueba
targetDb.rules.insertOne({
  name: "Example_Test_Rule",
  rule_text: `
rule Example_Test_Rule {
  strings:
    $a = "MALICIOUS"
  condition:
    $a
}`,
  tags: ["test", "malware"],
  enabled: true,
  created_at: new Date()
});

print("MongoDB initialized for YARA");
