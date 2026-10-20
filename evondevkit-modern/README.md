# evondevKit-Modern — Design System Kỹ Thuật Số Chuẩn Quốc Tế

Thư viện Design System tiên phong ứng dụng toàn diện các tiêu chuẩn Web CSS hiện đại nhất: **CSS Cascade Layers (`@layer`)**, **CUBE CSS Methodology**, hệ màu **OKLCH**, **CSS Container Queries (`@container`)**, và hoàn toàn tuân thủ tiêu chuẩn tiếp cận **WCAG 2.2 cấp độ AA**.

---

## 1. Kiến trúc CSS cốt lõi

### 1.1. CSS Cascade Layers (`@layer`)
Kiểm soát độ ưu tiên cascade dứt điểm mà không phụ thuộc vào độ đặc hiệu (specificity wars). Mã nguồn định nghĩa thứ tự rõ ràng từ thấp lên cao:

```css
@layer reset, tokens, base, composition, components, utilities;
```

*   `reset`: Đưa các phần tử mặc định của user-agent về chuẩn phẳng an toàn bằng `:where()`.
*   `tokens`: Chứa Design Tokens, Biến CSS toàn cục và hệ màu OKLCH.
*   `base`: Thiết lập typographic, focus indicator toàn cục và HTML tags.
*   `composition`: Các khung dựng hình không biên giới (Layout Primitives: Grid, Flex wrappers).
*   `components`: Thành phần UI độc lập (Buttons, Cards, Dialogs, Floating Inputs, Nav).
*   `utilities`: Các lớp đơn nhiệm với tính cưỡng chế cao nhất (`.u-sr-only`, `.u-text-center`).

### 1.2. Phương pháp luận CUBE CSS
Kết hợp tính linh hoạt của Utility-first với cấu trúc bài bản của BEM:
*   **Composition**: Layout-first độc lập với component, sử dụng CSS Grid/Flexbox tự co giãn (`.l-container`, `.l-flow`).
*   **Utility**: Chỉ sử dụng cho mục đích hiển thị duy nhất (`.u-sr-only`).
*   **Block**: Component có danh tính rõ ràng (`.c-card`, `.form-switch`, `.edk-header`).
*   **Exception**: Kiểm soát biến thể trạng thái dựa trên thuộc tính data-attribute hoặc ARIA state (`[aria-expanded="true"]`, `[data-theme="dark"]`).

### 1.3. Hệ màu OKLCH Tokens
OKLCH đem lại sự đồng đều thị giác (Perceptual Uniformity), loại bỏ hiện tượng sai lệch độ sáng khi chuyển sắc (hue shifting) thường gặp ở sRGB hoặc HSL.

```css
:root {
  --color-brand-primary: oklch(0.55 0.22 264);
  --color-brand-secondary: oklch(0.62 0.16 168);
  --color-surface-base: oklch(0.99 0.002 264);
  --color-text-primary: oklch(0.18 0.02 264);
}
```

*   **Dark Mode tức thời:** Chỉ cần thay đổi Lightness của Surface và Canvas, giữ nguyên Hue và Chroma để màu sắc thương hiệu hiển thị tự nhiên.
*   Hỗ trợ không gian màu P3 trên màn hình Wide Gamut cao cấp.

---

## 2. Bảng kiểm định Accessibility WCAG 2.2 AA

Design System được thiết kế và kiểm thử đạt chuẩn WCAG 2.2 Level AA:

| Tiêu chuẩn WCAG 2.2 | Yêu cầu kỹ thuật | Triển khai tại `evondevKit-Modern` | Kết quả |
| :--- | :--- | :--- | :--- |
| **1.4.3 Contrast (Minimum)** | Độ tương phản văn bản thường $\ge 4.5:1$, văn bản lớn $\ge 3:1$. | `color-text-primary` trên Canvas đạt tỷ lệ **14:1**. Dark Mode đạt **13:1**. | **ĐẠT (Pass)** |
| **1.4.11 Non-text Contrast** | Tương phản của UI Controls/Borders $\ge 3:1$. | Border các input và toggle switch sử dụng `oklch(0.72 ...)` đảm bảo phân biệt ranh giới rõ ràng. | **ĐẠT (Pass)** |
| **2.1.1 Keyboard Navigation** | Truy cập toàn bộ chức năng chỉ bằng bàn phím. | Điều hướng phím `Tab`, `Space`, `Enter`. Cung cấp thẻ `.skip-link` bỏ qua điều hướng header. | **ĐẠT (Pass)** |
| **2.4.7 Focus Visible** | Đường chỉ thị focus trực quan rõ nét. | Áp dụng `:focus-visible` với Double-Ring Pattern chống xung đột màu nền. | **ĐẠT (Pass)** |
| **2.5.8 Target Size (Minimum)** | Kích thước vùng bấm tối thiểu $24 \times 24\text{px}$ (khuyến nghị $\ge 44 \times 44\text{px}$). | Tất cả buttons, switch target và close buttons đều đảm bảo `min-height: 44px` và `min-width: 44px`. | **ĐẠT (Pass)** |
| **4.1.2 Name, Role, Value** | Phần tử tương tác hỗ trợ đúng vai trò Screen Reader. | Native `<dialog>` bẫy focus chuẩn (focus trap), `role="switch"`, `aria-checked`, `aria-labelledby`. | **ĐẠT (Pass)** |

---

## 3. Cấu trúc thư mục

```text
evondevkit-modern/
├── tokens/
│   └── tokens.css            # OKLCH colors, fluid typography/spacing, elevation
├── styles/
│   └── base.css              # Reset :where(), logical properties, global focus-visible
├── components/
│   ├── navigation/
│   │   ├── nav.css           # Header sticky, mobile drawer, 44x44 hamburger
│   │   └── nav.js            # ResponsiveNav class, focus trap, Escape key
│   ├── form/
│   │   ├── form.css          # Floating labels, :user-invalid, accessible switch
│   │   └── form.js           # FormValidator, AccessibleSwitch helper
│   ├── card/
│   │   └── card.css          # Container query card (@container card min-width: 420px)
│   └── modal/
│       ├── modal.css         # Native <dialog>, ::backdrop blur, @starting-style
│       └── modal.js          # AccessibleModal class, backdrop click, restore focus
├── index.html                # Interactive Showcase trang chủ với Theme Switcher
└── README.md                 # Tài liệu kỹ thuật và hướng dẫn sử dụng
```

---

## 4. Hướng dẫn sử dụng & Tích hợp

### 4.1. Khởi chạy Showcase Trực tiếp

Mở file [`index.html`](evondevkit-modern/index.html) bằng trình duyệt web hiện đại (Chrome 115+, Safari 16.4+, Firefox 113+, Edge 115+) hoặc qua bất kỳ HTTP static server nào (`npx serve`, `python -m http.server`).

### 4.2. Tích hợp Component vào Dự Án

```html
<!-- Nhập các stylesheet theo thứ tự layer -->
<link rel="stylesheet" href="./tokens/tokens.css">
<link rel="stylesheet" href="./styles/base.css">
<link rel="stylesheet" href="./components/navigation/nav.css">
<link rel="stylesheet" href="./components/card/card.css">
```

```javascript
// Khởi tạo các module JavaScript chuẩn ES6
import { ResponsiveNav } from './components/navigation/nav.js';
import { FormValidator, AccessibleSwitch } from './components/form/form.js';
import { AccessibleModal } from './components/modal/modal.js';

new ResponsiveNav();
AccessibleSwitch.initAll();
```
