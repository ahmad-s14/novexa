package com.novexa

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private val ACCOUNT_DEFAULT_LABELS = listOf(
    "Bank Name",
    "Name",
    "Account Number",
    "IBAN",
    "Phone Number",
    "Branch"
)
private val CARD_LABELS = listOf("Card Holder", "Card Number", "Expiry", "CVV", "Bank Name", "Notes")

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NovexaApp(activity = this)
        }
    }

    fun authenticate(onSuccess: () -> Unit, onFailure: () -> Unit) {
        val biometricManager = BiometricManager.from(this)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG

        if (biometricManager.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            onFailure()
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailure()
                }

                override fun onAuthenticationFailed() {
                    onFailure()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock novexa")
            .setSubtitle("Use biometrics to unlock your encrypted vault")
            .setAllowedAuthenticators(authenticators)
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(promptInfo)
    }
}

@Serializable
data class FieldValue(
    val key: String,
    val value: String,
    val isDefault: Boolean
)

@Serializable
data class AccountEntry(
    val id: String = UUID.randomUUID().toString(),
    val fields: List<FieldValue> = emptyList(),
    val customFields: List<FieldValue> = emptyList()
)

@Serializable
data class CardEntry(
    val id: String = UUID.randomUUID().toString(),
    val type: String = "Physical",
    val fields: List<FieldValue> = emptyList()
)

@Serializable
data class AppVault(
    val accounts: List<AccountEntry> = emptyList(),
    val cards: List<CardEntry> = emptyList()
)

class SecureVaultStore(private val activity: ComponentActivity) {
    private val json = Json { ignoreUnknownKeys = true }

    private val encryptedPrefs by lazy {
        val masterKey = MasterKey.Builder(activity)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            activity,
            "novexa_secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun loadVault(): AppVault {
        val raw = encryptedPrefs.getString("vault", null) ?: return AppVault()
        return runCatching { json.decodeFromString(AppVault.serializer(), raw) }.getOrDefault(AppVault())
    }

    fun saveVault(vault: AppVault) {
        encryptedPrefs.edit().putString("vault", json.encodeToString(vault)).apply()
    }

    fun loadDarkMode(): Boolean = encryptedPrefs.getBoolean("dark_mode", false)

    fun saveDarkMode(value: Boolean) {
        encryptedPrefs.edit().putBoolean("dark_mode", value).apply()
    }

    fun backup(passphrase: String): File {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = deriveKey(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val payload = json.encodeToString(loadVault()).toByteArray()
        val encrypted = cipher.doFinal(payload)
        val output = ByteArray(salt.size + iv.size + encrypted.size)
        System.arraycopy(salt, 0, output, 0, salt.size)
        System.arraycopy(iv, 0, output, salt.size, iv.size)
        System.arraycopy(encrypted, 0, output, salt.size + iv.size, encrypted.size)
        val file = File(activity.filesDir, "novexa_backup.bin")
        file.writeBytes(output)
        return file
    }

    fun restore(passphrase: String): Boolean {
        val file = File(activity.filesDir, "novexa_backup.bin")
        if (!file.exists()) return false
        val all = file.readBytes()
        if (all.size < 29) return false
        val salt = all.copyOfRange(0, 16)
        val iv = all.copyOfRange(16, 28)
        val encrypted = all.copyOfRange(28, all.size)
        val key = deriveKey(passphrase, salt)
        return runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val raw = cipher.doFinal(encrypted)
            val vault = json.decodeFromString(AppVault.serializer(), String(raw))
            saveVault(vault)
            true
        }.getOrDefault(false)
    }

    private fun deriveKey(passphrase: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, 65_536, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }
}

private fun orderedAccountFields(fields: List<FieldValue>): List<FieldValue> {
    val byKey = fields.associateBy { it.key }
    val orderedDefaults = ACCOUNT_DEFAULT_LABELS.map { key ->
        byKey[key] ?: FieldValue(key = key, value = "", isDefault = true)
    }
    val remaining = fields.filterNot { field -> ACCOUNT_DEFAULT_LABELS.contains(field.key) }
    return orderedDefaults + remaining
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NovexaApp(activity: MainActivity) {
    val context = LocalContext.current
    val store = remember { SecureVaultStore(activity) }
    var isUnlocked by remember { mutableStateOf(false) }
    var darkMode by remember { mutableStateOf(store.loadDarkMode()) }
    var tabIndex by remember { mutableStateOf(0) }
    var showSettings by remember { mutableStateOf(false) }
    var vault by remember { mutableStateOf(store.loadVault()) }
    var hasPromptedForUnlock by remember { mutableStateOf(false) }

    MaterialTheme(colorScheme = if (darkMode) darkColorScheme() else lightColorScheme()) {
        val statusBarColor = MaterialTheme.colorScheme.surface.toArgb()
        DisposableEffect(darkMode, statusBarColor) {
            activity.window.statusBarColor = statusBarColor
            WindowCompat.getInsetsController(activity.window, activity.window.decorView)
                ?.isAppearanceLightStatusBars = !darkMode
            onDispose {}
        }

        if (!isUnlocked) {
            var authError by remember { mutableStateOf<String?>(null) }
            val unlock: () -> Unit = {
                activity.authenticate(
                    onSuccess = { isUnlocked = true },
                    onFailure = {
                        authError = "Biometric unlock failed. Please try again."
                    }
                )
            }

            LaunchedEffect(hasPromptedForUnlock) {
                if (!hasPromptedForUnlock) {
                    hasPromptedForUnlock = true
                    unlock()
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(8.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("novexa", style = MaterialTheme.typography.headlineMedium)
                        Text(
                            "Securely unlock your vault with biometrics.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        authError?.let {
                            Text(it, color = MaterialTheme.colorScheme.error)
                        }
                        Button(onClick = unlock, modifier = Modifier.fillMaxWidth()) {
                            Text("Retry biometric unlock")
                        }
                    }
                }
            }
            return@MaterialTheme
        }

        if (showSettings) {
            SettingsDialog(
                vault = vault,
                darkMode = darkMode,
                onDarkModeChange = {
                    darkMode = it
                    store.saveDarkMode(it)
                },
                onDismiss = { showSettings = false },
                onBackup = { passphrase ->
                    val file = store.backup(passphrase)
                    Toast.makeText(context, "Backup saved to ${file.absolutePath}", Toast.LENGTH_LONG).show()
                },
                onRestore = { passphrase ->
                    if (store.restore(passphrase)) {
                        vault = store.loadVault()
                        Toast.makeText(context, "Backup restored", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "Restore failed", Toast.LENGTH_SHORT).show()
                    }
                },
                onUpdateVault = {
                    vault = it
                    store.saveVault(it)
                }
            )
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("novexa") },
                    actions = {
                        IconButton(onClick = { showSettings = true }) {
                            Icon(Icons.Default.Settings, contentDescription = "Settings")
                        }
                    }
                )
            }
        ) { padding ->
            Column(Modifier.padding(padding)) {
                TabRow(selectedTabIndex = tabIndex) {
                    Tab(selected = tabIndex == 0, onClick = { tabIndex = 0 }, text = { Text("Accounts") })
                    Tab(selected = tabIndex == 1, onClick = { tabIndex = 1 }, text = { Text("Debit Cards") })
                }
                if (tabIndex == 0) {
                    AccountsTab(accounts = vault.accounts)
                } else {
                    CardsTab(cards = vault.cards)
                }
            }
        }
    }
}

@Composable
fun AccountsTab(accounts: List<AccountEntry>) {
    val clipboard = LocalClipboardManager.current
    var expandedCustomId by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (accounts.isEmpty()) {
            item {
                Text("No accounts yet. Add new entries from Settings.")
            }
        }

        items(accounts, key = { it.id }) { account ->
            val visibleDefaults = remember(account.id, account.fields) {
                orderedAccountFields(account.fields).filter { it.value.isNotBlank() }
            }
            val visibleCustom = account.customFields.filter { it.value.isNotBlank() }

            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Account")
                    visibleDefaults.forEach { field ->
                        FieldRow(field = field, onCopy = { clipboard.setText(AnnotatedString(field.value)) })
                    }
                    if (visibleCustom.isNotEmpty()) {
                        Text(
                            text = if (expandedCustomId == account.id) "Custom fields ▼" else "Custom fields ▶",
                            modifier = Modifier.clickable {
                                expandedCustomId = if (expandedCustomId == account.id) null else account.id
                            }
                        )
                        if (expandedCustomId == account.id) {
                            visibleCustom.forEach { field ->
                                FieldRow(field = field, onCopy = { clipboard.setText(AnnotatedString(field.value)) })
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun CardsTab(cards: List<CardEntry>) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (cards.isEmpty()) {
            item {
                Text("No cards yet. Add new entries from Settings.")
            }
        }

        items(cards, key = { it.id }) { card ->
            val visibleFields = card.fields.filter { it.value.isNotBlank() }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${card.type} card")
                    visibleFields.forEach { field ->
                        FieldRow(field = field, onCopy = { clipboard.setText(AnnotatedString(field.value)) })
                    }
                }
            }
        }
    }
}

@Composable
fun FieldRow(field: FieldValue, onCopy: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(field.key, style = MaterialTheme.typography.labelMedium)
            Text(field.value)
        }
        IconButton(onClick = onCopy) {
            Icon(Icons.Default.ContentCopy, contentDescription = "Copy")
        }
    }
}

@Composable
fun SettingsDialog(
    vault: AppVault,
    darkMode: Boolean,
    onDarkModeChange: (Boolean) -> Unit,
    onDismiss: () -> Unit,
    onBackup: (String) -> Unit,
    onRestore: (String) -> Unit,
    onUpdateVault: (AppVault) -> Unit
) {
    var passphrase by remember { mutableStateOf("") }

    val newAccountValues = remember { mutableStateListOf(*Array(ACCOUNT_DEFAULT_LABELS.size) { "" }) }
    val newAccountCustomFields = remember { mutableStateListOf<FieldValue>() }
    var newAccountCustomKey by remember { mutableStateOf("") }
    var newAccountCustomValue by remember { mutableStateOf("") }

    var newCardType by remember { mutableStateOf("Physical") }
    val newCardValues = remember { mutableStateListOf(*Array(CARD_LABELS.size) { "" }) }

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("Settings") },
        text = {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Dark theme")
                        Switch(checked = darkMode, onCheckedChange = onDarkModeChange)
                    }
                }
                item {
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("Backup passphrase") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { if (passphrase.isNotBlank()) onBackup(passphrase) }) { Text("Backup") }
                        Button(onClick = { if (passphrase.isNotBlank()) onRestore(passphrase) }) { Text("Restore") }
                    }
                }

                item { Text("Add account") }
                item {
                    ACCOUNT_DEFAULT_LABELS.forEachIndexed { index, label ->
                        OutlinedTextField(
                            value = newAccountValues[index],
                            onValueChange = { newAccountValues[index] = it },
                            label = { Text(label) },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(6.dp))
                    }
                    OutlinedTextField(
                        value = newAccountCustomKey,
                        onValueChange = { newAccountCustomKey = it },
                        label = { Text("Custom field name") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = newAccountCustomValue,
                        onValueChange = { newAccountCustomValue = it },
                        label = { Text("Custom field value") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(6.dp))
                    Button(onClick = {
                        if (newAccountCustomKey.isNotBlank()) {
                            newAccountCustomFields.add(
                                FieldValue(
                                    key = newAccountCustomKey,
                                    value = newAccountCustomValue,
                                    isDefault = false
                                )
                            )
                            newAccountCustomKey = ""
                            newAccountCustomValue = ""
                        }
                    }) {
                        Text("Add custom field")
                    }
                    Spacer(Modifier.height(6.dp))
                    Button(onClick = {
                        val defaults = ACCOUNT_DEFAULT_LABELS.mapIndexed { index, label ->
                            FieldValue(key = label, value = newAccountValues[index], isDefault = true)
                        }
                        val updated = vault.copy(
                            accounts = vault.accounts + AccountEntry(
                                fields = defaults,
                                customFields = newAccountCustomFields.toList()
                            )
                        )
                        onUpdateVault(updated)
                        newAccountValues.indices.forEach { newAccountValues[it] = "" }
                        newAccountCustomFields.clear()
                    }) {
                        Text("Save account")
                    }
                }

                item { Text("Add debit card") }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = newCardType == "Physical",
                            onClick = { newCardType = "Physical" },
                            label = { Text("Physical") }
                        )
                        FilterChip(
                            selected = newCardType == "Virtual",
                            onClick = { newCardType = "Virtual" },
                            label = { Text("Virtual") }
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    CARD_LABELS.forEachIndexed { index, label ->
                        OutlinedTextField(
                            value = newCardValues[index],
                            onValueChange = { newCardValues[index] = it },
                            label = { Text(label) },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(6.dp))
                    }
                    Button(onClick = {
                        val fields = CARD_LABELS.mapIndexed { index, label ->
                            FieldValue(key = label, value = newCardValues[index], isDefault = true)
                        }
                        val updated = vault.copy(
                            cards = vault.cards + CardEntry(type = newCardType, fields = fields)
                        )
                        onUpdateVault(updated)
                        newCardValues.indices.forEach { newCardValues[it] = "" }
                    }) {
                        Text("Save card")
                    }
                }

                item { Text("Manage accounts") }
                items(vault.accounts, key = { it.id }) { account ->
                    val editableDefaults = remember(account.id) {
                        mutableStateListOf(
                            *ACCOUNT_DEFAULT_LABELS.map { key ->
                                account.fields.firstOrNull { it.key == key }?.value.orEmpty()
                            }.toTypedArray()
                        )
                    }
                    val editableCustom = remember(account.id) {
                        mutableStateListOf(*account.customFields.map { it.value }.toTypedArray())
                    }

                    Card {
                        Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            ACCOUNT_DEFAULT_LABELS.forEachIndexed { index, label ->
                                OutlinedTextField(
                                    value = editableDefaults[index],
                                    onValueChange = { editableDefaults[index] = it },
                                    label = { Text(label) },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                            account.customFields.forEachIndexed { index, field ->
                                OutlinedTextField(
                                    value = editableCustom[index],
                                    onValueChange = { editableCustom[index] = it },
                                    label = { Text(field.key) },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    onUpdateVault(vault.copy(accounts = vault.accounts.filterNot { it.id == account.id }))
                                }) { Text("Delete") }
                                Button(onClick = {
                                    val editedDefaults = ACCOUNT_DEFAULT_LABELS.mapIndexed { index, label ->
                                        FieldValue(key = label, value = editableDefaults[index], isDefault = true)
                                    }
                                    val editedCustom = account.customFields.mapIndexed { index, field ->
                                        FieldValue(key = field.key, value = editableCustom[index], isDefault = false)
                                    }
                                    val edited = account.copy(
                                        fields = editedDefaults,
                                        customFields = editedCustom
                                    )
                                    onUpdateVault(vault.copy(accounts = vault.accounts.map { if (it.id == account.id) edited else it }))
                                }) { Text("Edit") }
                            }
                        }
                    }
                }

                item { Text("Manage cards") }
                items(vault.cards, key = { it.id }) { card ->
                    val editableCardType = remember(card.id) { mutableStateOf(card.type) }
                    val editableCardValues = remember(card.id) {
                        mutableStateListOf(
                            *CARD_LABELS.map { label ->
                                card.fields.firstOrNull { it.key == label }?.value.orEmpty()
                            }.toTypedArray()
                        )
                    }

                    Card {
                        Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                FilterChip(
                                    selected = editableCardType.value == "Physical",
                                    onClick = { editableCardType.value = "Physical" },
                                    label = { Text("Physical") }
                                )
                                FilterChip(
                                    selected = editableCardType.value == "Virtual",
                                    onClick = { editableCardType.value = "Virtual" },
                                    label = { Text("Virtual") }
                                )
                            }
                            CARD_LABELS.forEachIndexed { index, label ->
                                OutlinedTextField(
                                    value = editableCardValues[index],
                                    onValueChange = { editableCardValues[index] = it },
                                    label = { Text(label) },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    onUpdateVault(vault.copy(cards = vault.cards.filterNot { it.id == card.id }))
                                }) { Text("Delete") }
                                Button(onClick = {
                                    val editedFields = CARD_LABELS.mapIndexed { index, label ->
                                        FieldValue(key = label, value = editableCardValues[index], isDefault = true)
                                    }
                                    val edited = card.copy(type = editableCardType.value, fields = editedFields)
                                    onUpdateVault(vault.copy(cards = vault.cards.map { if (it.id == card.id) edited else it }))
                                }) { Text("Edit") }
                            }
                        }
                    }
                }
            }
        }
    )
}
