package com.novexa

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.width
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
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
import androidx.compose.ui.platform.LocalView
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
import java.security.MessageDigest
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
private val CARD_DEFAULT_LABELS = listOf("Card Holder", "Card Number", "Expiry", "CVV", "Bank Name", "Notes")

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

private fun normalizeAccountFields(fields: List<FieldValue>): List<FieldValue> {
    val byKey = fields.associateBy { it.key }
    return ACCOUNT_DEFAULT_LABELS.map { label ->
        when (label) {
            "Branch" -> byKey["Branch"] ?: byKey["Branch Name"] ?: FieldValue(label, "", true)
            else -> byKey[label] ?: FieldValue(label, "", true)
        }
    }
}

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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NovexaApp(activity: MainActivity) {
    val context = LocalContext.current
    val view = LocalView.current
    val store = remember { SecureVaultStore(activity) }
    var isUnlocked by remember { mutableStateOf(false) }
    var darkMode by remember { mutableStateOf(store.loadDarkMode()) }
    var tabIndex by remember { mutableStateOf(0) }
    var showSettings by remember { mutableStateOf(false) }
    var vault by remember { mutableStateOf(store.loadVault()) }
    var authInProgress by remember { mutableStateOf(false) }
    var authError by remember { mutableStateOf<String?>(null) }

    fun startBiometricUnlock() {
        if (authInProgress) return
        authInProgress = true
        authError = null
        activity.authenticate(
            onSuccess = {
                isUnlocked = true
                authInProgress = false
            },
            onFailure = {
                authInProgress = false
                authError = "Biometric unlock failed. Try again."
            }
        )
    }

    MaterialTheme(colorScheme = if (darkMode) darkColorScheme() else lightColorScheme()) {
        SideEffect {
            if (!view.isInEditMode) {
                activity.window.statusBarColor = MaterialTheme.colorScheme.surface.toArgb()
                WindowCompat.getInsetsController(activity.window, view).isAppearanceLightStatusBars = !darkMode
            }
        }

        if (!isUnlocked) {
            LaunchedEffect(Unit) {
                startBiometricUnlock()
            }
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background)
                    .padding(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Card(Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("novexa", style = MaterialTheme.typography.headlineMedium)
                        Text(
                            "Unlock your vault with biometrics.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        authError?.let {
                            Text(
                                text = it,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        Button(
                            onClick = { startBiometricUnlock() },
                            enabled = !authInProgress
                        ) {
                            Text(if (authInProgress) "Waiting for biometrics..." else "Unlock with biometrics")
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
                onAddAccount = { account ->
                    vault = vault.copy(accounts = vault.accounts + account)
                    store.saveVault(vault)
                    Toast.makeText(context, "Account saved", Toast.LENGTH_SHORT).show()
                },
                onAddCard = { card ->
                    vault = vault.copy(cards = vault.cards + card)
                    store.saveVault(vault)
                    Toast.makeText(context, "Card saved", Toast.LENGTH_SHORT).show()
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
                    AccountsTab(
                        accounts = vault.accounts,
                        onSave = {
                            vault = vault.copy(accounts = it)
                            store.saveVault(vault)
                        }
                    )
                } else {
                    CardsTab(
                        cards = vault.cards,
                        onSave = {
                            vault = vault.copy(cards = it)
                            store.saveVault(vault)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun AccountsTab(accounts: List<AccountEntry>, onSave: (List<AccountEntry>) -> Unit) {
    val clipboard = LocalClipboardManager.current
    var expandedCustomId by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item { Text("Add account entries from Settings.", style = MaterialTheme.typography.bodyMedium) }

        items(accounts, key = { it.id }) { account ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Account")
                    normalizeAccountFields(account.fields)
                        .filter { it.value.isNotBlank() }
                        .forEach { field ->
                        FieldRow(field = field, onCopy = { clipboard.setText(AnnotatedString(field.value)) })
                    }
                    val nonEmptyCustom = account.customFields.filter { it.value.isNotBlank() }
                    if (nonEmptyCustom.isNotEmpty()) {
                        Text(
                            text = if (expandedCustomId == account.id) "Custom fields ▼" else "Custom fields ▶",
                            modifier = Modifier.clickable {
                                expandedCustomId = if (expandedCustomId == account.id) null else account.id
                            }
                        )
                        if (expandedCustomId == account.id) {
                            nonEmptyCustom.forEach { field ->
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
fun CardsTab(cards: List<CardEntry>, onSave: (List<CardEntry>) -> Unit) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item { Text("Add card entries from Settings.", style = MaterialTheme.typography.bodyMedium) }

        items(cards, key = { it.id }) { card ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${card.type} card")
                    card.fields
                        .filter { it.value.isNotBlank() }
                        .forEach { field ->
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
    onSavePin: (String) -> Unit,
    onBackup: (String) -> Unit,
    onRestore: (String) -> Unit,
    onUpdateVault: (AppVault) -> Unit
) {
    var pin by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }

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
                        value = pin,
                        onValueChange = { pin = it.filter(Char::isDigit).take(MAX_PIN_LENGTH) },
                        label = { Text("Set PIN") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text("PIN length: $MIN_PIN_LENGTH-$MAX_PIN_LENGTH digits")
                    Button(onClick = { if (pin.length >= MIN_PIN_LENGTH) onSavePin(pin) }) {
                        Text("Save PIN")
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

                item { Text("Manage accounts") }
                items(vault.accounts, key = { it.id }) { account ->
                    var editableName by remember(account.id) {
                        mutableStateOf(account.fields.firstOrNull { it.key == "Name" }?.value.orEmpty())
                    }
                    Card {
                        Column(Modifier.padding(8.dp)) {
                            OutlinedTextField(
                                value = editableName,
                                onValueChange = { editableName = it },
                                label = { Text("Account name") },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    onUpdateVault(vault.copy(accounts = vault.accounts.filterNot { it.id == account.id }))
                                }) { Text("Delete") }
                                Button(onClick = {
                                    val edited = account.copy(
                                        fields = account.fields.map {
                                            if (it.key == "Name") it.copy(value = editableName) else it
                                        }
                                    )
                                    onUpdateVault(vault.copy(accounts = vault.accounts.map { if (it.id == account.id) edited else it }))
                                }) { Text("Edit") }
                            }
                        }
                    }
                }

                item { Text("Manage cards") }
                items(vault.cards, key = { it.id }) { card ->
                    var editableHolder by remember(card.id) {
                        mutableStateOf(card.fields.firstOrNull { it.key == "Card Holder" }?.value.orEmpty())
                    }
                    Card {
                        Column(Modifier.padding(8.dp)) {
                            OutlinedTextField(
                                value = editableHolder,
                                onValueChange = { editableHolder = it },
                                label = { Text("Card holder") },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    onUpdateVault(vault.copy(cards = vault.cards.filterNot { it.id == card.id }))
                                }) { Text("Delete") }
                                Button(onClick = {
                                    val edited = card.copy(
                                        fields = card.fields.map {
                                            if (it.key == "Card Holder") it.copy(value = editableHolder) else it
                                        }
                                    )
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
